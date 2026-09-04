/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/runtime/controller.hpp"

#include <atomic>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#if !defined(_WIN32)
#include <unistd.h>
#endif

#include <boost/asio/io_context.hpp>

#include "core/security/identity.hpp"
#include "server/runtime/local_runtime.hpp"
#include "server/runtime/manager.hpp"
#include "server/runtime/security_config.hpp"

namespace yume::server {

namespace {

std::string listen_endpoint_for(ServerConfig const& cfg) {
    const std::string host = cfg.listen_address.empty()
        ? std::string("0.0.0.0")
        : cfg.listen_address;
    return host + ":" + std::to_string(cfg.listen_port);
}

int worker_count_for(ServerConfig const& cfg) {
    if (cfg.threads > 0) return cfg.threads;
    const unsigned int hw = std::thread::hardware_concurrency();
    return static_cast<int>(hw > 0 ? hw : 1);
}

bool privileged_port_requires_elevation(int port) {
#if defined(_WIN32)
    (void)port;
    return false;
#else
    return port > 0 && port < 1024 && ::geteuid() != 0;
#endif
}

bool is_embedded_read_operation(std::string_view op) {
    return op == "runtime.info" || op == "runtime.status" ||
           op == "runtime.sessions" || op == "runtime.events" ||
           op == "directory.list" || op == "federation.status" ||
           op == "federation.topology";
}

}  // namespace

struct RuntimeController::Impl {
    // Lifecycle operations take lifecycle_mtx before mtx. Read-only snapshots
    // take only mtx. This prevents start from publishing a new manager after a
    // concurrent stop has already observed an empty controller.
    std::mutex lifecycle_mtx;
    mutable std::mutex mtx;
    ServerConfig cfg;
    Status status;
    std::unique_ptr<boost::asio::io_context> io;
    std::shared_ptr<Manager> manager;
    std::shared_ptr<LocalRuntime> local_runtime;
    std::vector<std::thread> workers;
    std::atomic<bool> running{false};
    std::atomic<bool> runtime_stop_requested{false};

    void request_stop_from_runtime() {
        // This callback can arrive while start() still owns local (unpublished)
        // resources. Publish intent first; start() rechecks it under mtx before
        // committing those resources.
        runtime_stop_requested.store(true, std::memory_order_release);
        std::lock_guard<std::mutex> lock(mtx);
        running.store(false);
        status.running = false;
        status.message = "stopped by local runtime request";
        if (manager) manager->stop();
        // Manager::stop cancels every persistent producer and posts bounded
        // session shutdown. Keep the context alive so those handlers can
        // release Session-owned callbacks instead of stranding self-cycles.
    }
};

RuntimeController::RuntimeController()
    : impl_(std::make_unique<Impl>()) {}

RuntimeController::~RuntimeController() {
    stop();
}

bool RuntimeController::start(
    ServerConfig cfg,
    std::string* error,
    runtime::OperationStatus* operation_status) {
    if (error) error->clear();
    runtime::SetOperationStatus(
        operation_status, runtime::OperationStatus::InternalError);
    std::unique_lock<std::mutex> lifecycle_lock(impl_->lifecycle_mtx);

    // Record the failure on impl_->status so a subsequent status() poll
    // returns it — without this, the GUI sees `running=false, message=""`
    // and the user has no idea why nothing happened.
    auto fail_with = [&](std::string msg,
                         runtime::OperationStatus status =
                             runtime::OperationStatus::InternalError) {
        if (error) *error = msg;
        runtime::SetOperationStatus(operation_status, status);
        std::lock_guard<std::mutex> lock(impl_->mtx);
        impl_->status.running = false;
        impl_->status.message = std::move(msg);
        return false;
    };

    if (privileged_port_requires_elevation(cfg.listen_port)) {
        return fail_with("listen port " + std::to_string(cfg.listen_port) +
                         " requires root or cap_net_bind_service",
                         runtime::OperationStatus::PermissionDenied);
    }

    {
        bool still_unwinding = false;
        {
            std::lock_guard<std::mutex> lock(impl_->mtx);
            if (impl_->running.load()) {
                runtime::SetOperationStatus(
                    operation_status,
                    runtime::OperationStatus::AlreadyRunning);
                if (error) {
                    *error = "server runtime is already running";
                }
                return false;
            }
            still_unwinding = impl_->io || impl_->manager ||
                              !impl_->workers.empty();
        }
        if (still_unwinding) {
            return fail_with("server runtime is still stopping",
                             runtime::OperationStatus::WouldBlock);
        }
    }
    impl_->runtime_stop_requested.store(false, std::memory_order_release);

    std::string security_error;
    if (!prepare_v2_security_config(cfg, false, &security_error)) {
        return fail_with(security_error.empty()
                             ? "server security configuration is invalid"
                             : std::move(security_error),
                         runtime::OperationStatus::InvalidArgument);
    }

    auto io = std::make_unique<boost::asio::io_context>(worker_count_for(cfg));
    std::shared_ptr<Manager> manager;
    try {
        manager = std::make_shared<Manager>(*io, cfg);
    } catch (std::exception const& ex) {
        return fail_with(ex.what());
    }
    const std::string ipc_path = local_runtime_path_for(cfg);

    auto runtime = std::make_shared<LocalRuntime>(
        ipc_path,
        manager.get(),
        [this]() { impl_->request_stop_from_runtime(); });

    std::string ipc_warning;
    try {
        if (cfg.ipc_enable && !runtime->start(&ipc_warning)) {
            ipc_warning = ipc_warning.empty()
                              ? "local runtime IPC unavailable"
                              : "local runtime IPC unavailable: " + ipc_warning;
        }
        manager->start();
    } catch (std::exception const& ex) {
        runtime->stop();
        manager->stop();
        io->stop();
        return fail_with(ex.what());
    }

    std::vector<std::thread> workers;
    const int workers_count = worker_count_for(cfg);
    auto rollback_worker_start = [&]() {
        // Worker creation can fail after earlier workers have entered run().
        // Stop every producer first, then the io_context, before joining so
        // the local vector never destroys a joinable std::thread.
        try {
            runtime->stop();
        } catch (...) {
        }
        try {
            manager->stop();
        } catch (...) {
        }
        try {
            io->stop();
        } catch (...) {
        }
        for (auto& worker : workers) {
            if (worker.joinable()) worker.join();
        }
    };

    try {
        workers.reserve(static_cast<std::size_t>(workers_count));
        for (int i = 0; i < workers_count; ++i) {
            workers.emplace_back([raw = io.get()]() { raw->run(); });
        }
    } catch (std::exception const& ex) {
        rollback_worker_start();
        return fail_with(std::string("failed to start server worker threads: ") +
                         ex.what());
    } catch (...) {
        rollback_worker_start();
        return fail_with("failed to start server worker threads: unknown error");
    }

    bool cancelled_before_publish = false;
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        cancelled_before_publish = impl_->runtime_stop_requested.load(
            std::memory_order_acquire);
        if (!cancelled_before_publish) {
            impl_->cfg = std::move(cfg);
            impl_->status.running = true;
            impl_->status.listen_endpoint = listen_endpoint_for(impl_->cfg);
            impl_->status.ipc_path = ipc_path;
            impl_->status.started = std::chrono::system_clock::now();
            impl_->status.message = ipc_warning.empty() ? "running" : ipc_warning;
            impl_->io = std::move(io);
            impl_->manager = std::move(manager);
            impl_->local_runtime = std::move(runtime);
            impl_->workers = std::move(workers);
            impl_->running.store(true);
        }
    }
    if (cancelled_before_publish) {
        rollback_worker_start();
        return fail_with("server startup was cancelled",
                         runtime::OperationStatus::NotRunning);
    }

    runtime::SetOperationStatus(
        operation_status, runtime::OperationStatus::Success);
    return true;
}

bool RuntimeController::stop() {
    std::unique_lock<std::mutex> lifecycle_lock(impl_->lifecycle_mtx);
    std::unique_ptr<boost::asio::io_context> io;
    std::shared_ptr<Manager> manager;
    std::shared_ptr<LocalRuntime> local_runtime;
    std::vector<std::thread> workers;

    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        if (!impl_->running.load() && !impl_->io && impl_->workers.empty()) {
            return false;
        }
        impl_->running.store(false);
        impl_->status.running = false;
        impl_->status.message = "stopped";
        local_runtime = std::move(impl_->local_runtime);
        manager = std::move(impl_->manager);
        io = std::move(impl_->io);
        workers = std::move(impl_->workers);
    }

    // The moved-out workers are joinable, so nothing between here and the
    // join loop may unwind past it: destroying a joinable std::thread calls
    // std::terminate, and this function also runs from the destructor. A
    // teardown failure is therefore contained, the join still happens, and
    // the failure is reported through the status message instead of an
    // exception.
    std::string teardown_error;
    const auto contain = [&teardown_error](const char* stage, auto&& step) {
        try {
            step();
        } catch (const std::exception& ex) {
            if (teardown_error.empty()) {
                teardown_error = std::string(stage) + ": " + ex.what();
            }
        } catch (...) {
            if (teardown_error.empty()) {
                teardown_error = std::string(stage) + ": unknown error";
            }
        }
    };
    if (local_runtime) {
        contain("local runtime stop", [&] { local_runtime->stop(); });
    }
    if (manager) {
        contain("manager stop", [&] { manager->stop(); });
    }
    // Do not stop the context before its shutdown handlers run. Manager
    // cancellation removes the accept/timer work, and each session has a
    // bounded transport-close deadline, so run() can drain and return.
    for (auto& worker : workers) {
        if (worker.joinable()) worker.join();
    }
    if (io) {
        contain("io context stop", [&] { io->stop(); });
    }
    if (!teardown_error.empty()) {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        impl_->status.message = "stopped; teardown error: " + teardown_error;
    }
    return true;
}

bool RuntimeController::running() const {
    return impl_->running.load();
}

bool RuntimeController::reload_auth(
    std::string* error,
    runtime::OperationStatus* operation_status) {
    if (error) error->clear();
    runtime::SetOperationStatus(
        operation_status, runtime::OperationStatus::InternalError);
    std::unique_lock<std::mutex> lifecycle_lock(impl_->lifecycle_mtx);
    std::shared_ptr<Manager> manager;
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        manager = impl_->manager;
    }
    if (!manager) {
        if (error) *error = "server runtime is not running";
        runtime::SetOperationStatus(
            operation_status, runtime::OperationStatus::NotRunning);
        return false;
    }
    if (!manager->reload_auth(error)) {
        return false;
    }
    runtime::SetOperationStatus(
        operation_status, runtime::OperationStatus::Success);
    return true;
}

RuntimeController::Status RuntimeController::status() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    Status out = impl_->status;
    out.running = impl_->running.load();
    if (impl_->manager) {
        out.active_sessions = impl_->manager->list_endpoint_statuses().size();
    }
    return out;
}

std::vector<RuntimeController::SessionSnapshot> RuntimeController::sessions() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    std::vector<SessionSnapshot> out;
    if (!impl_->manager) return out;
    for (auto const& status : impl_->manager->list_endpoint_statuses()) {
        SessionSnapshot s;
        s.endpoint_id = status.endpoint.endpoint_id;
        s.display_name = status.endpoint.display_name;
        s.client_platform = status.endpoint.client_platform;
        s.client_version = status.endpoint.client_version;
        if (status.latest_lifecycle) {
            s.state = status.latest_lifecycle->state;
        } else {
            s.state = status.endpoint.online ? "online" : "offline";
        }
        out.push_back(std::move(s));
    }
    return out;
}

bool RuntimeController::register_service(
    const std::string& service,
    std::string* error,
    runtime::OperationStatus* operation_status) {
    if (error) error->clear();
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!impl_->manager) {
        if (error) *error = "server runtime is not running";
        runtime::SetOperationStatus(
            operation_status, runtime::OperationStatus::NotRunning);
        return false;
    }
    return impl_->manager->register_service(
        service, error, operation_status);
}

std::shared_ptr<runtime::ServiceStream> RuntimeController::accept_service_stream(
    const std::string& service,
    std::uint32_t timeout_ms,
    std::string* error,
    runtime::OperationStatus* operation_status) {
    if (error) error->clear();
    std::shared_ptr<Manager> manager;
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        manager = impl_->manager;
    }
    if (!manager) {
        if (error) *error = "server runtime is not running";
        runtime::SetOperationStatus(
            operation_status, runtime::OperationStatus::NotRunning);
        return {};
    }
    return manager->accept_service_stream(
        service, timeout_ms, error, operation_status);
}

nlohmann::json RuntimeController::request(
        std::string const& op,
        nlohmann::json const& args,
        std::string* error,
        runtime::OperationStatus* operation_status) const {
    if (error) error->clear();
    if (op.empty()) {
        runtime::SetOperationStatus(
            operation_status, runtime::OperationStatus::InvalidArgument);
        if (error) *error = "operation name is empty";
        return nlohmann::json::object();
    }
    if (!args.is_object()) {
        runtime::SetOperationStatus(
            operation_status, runtime::OperationStatus::InvalidArgument);
        if (error) *error = "operation arguments must be a JSON object";
        return nlohmann::json::object();
    }

    // The local runtime holds a non-owning Manager pointer, so the Manager
    // handle is held across the call too: a concurrent stop() moves both out
    // under this same mutex and would otherwise destroy the Manager while the
    // operation is still reading it.
    std::shared_ptr<LocalRuntime> runtime;
    std::shared_ptr<Manager> manager;
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        if (impl_->running.load()) {
            runtime = impl_->local_runtime;
            manager = impl_->manager;
        }
    }
    if (!runtime || !manager) {
        runtime::SetOperationStatus(
            operation_status, runtime::OperationStatus::NotRunning);
        if (error) *error = "server runtime is not running";
        return nlohmann::json::object();
    }

    if (!is_embedded_read_operation(op)) {
        runtime::SetOperationStatus(
            operation_status, runtime::OperationStatus::Success);
        return {
            {"ok", false},
            {"error",
             "operation is not available through the read-only embedded "
             "server API"},
        };
    }

    nlohmann::json response;
    try {
        response = runtime->handle_request({{"op", op}, {"args", args}});
    } catch (std::exception const& ex) {
        runtime::SetOperationStatus(
            operation_status, runtime::OperationStatus::InternalError);
        if (error) *error = ex.what();
        return nlohmann::json::object();
    }

    if (!response.is_object() || !response.contains("ok") ||
        !response["ok"].is_boolean()) {
        runtime::SetOperationStatus(
            operation_status, runtime::OperationStatus::InternalError);
        if (error) *error = "server operation returned an invalid envelope";
        return nlohmann::json::object();
    }

    runtime::SetOperationStatus(
        operation_status, runtime::OperationStatus::Success);
    return response;
}

ServerConfig RuntimeController::config() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->cfg;
}

std::string RuntimeController::instance_key_for(ServerConfig const& cfg,
                                                std::string const& config_path) {
    if (!cfg.ipc_path.empty()) return cfg.ipc_path;
    if (!cfg.server_id.empty()) return cfg.server_id;
    return yume::identity::derive_instance_key(
        std::to_string(cfg.listen_port) + "|" + cfg.tls_cert + "|" +
        cfg.auth_keys + "|" + config_path);
}

std::string RuntimeController::local_runtime_path_for(ServerConfig const& cfg,
                                                      std::string const& config_path) {
    if (!cfg.ipc_path.empty()) return cfg.ipc_path;
    return LocalRuntime::socket_path_for(instance_key_for(cfg, config_path));
}

}  // namespace yume::server
