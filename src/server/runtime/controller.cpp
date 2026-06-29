/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/runtime/controller.hpp"

#include <atomic>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>

#if !defined(_WIN32)
#include <unistd.h>
#endif

#include <boost/asio.hpp>

#include "core/security/identity.hpp"
#include "server/runtime/local_runtime.hpp"
#include "server/runtime/manager.hpp"

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

}  // namespace

struct RuntimeController::Impl {
    mutable std::mutex mtx;
    ServerConfig cfg;
    Status status;
    std::unique_ptr<boost::asio::io_context> io;
    std::shared_ptr<Manager> manager;
    std::shared_ptr<LocalRuntime> local_runtime;
    std::vector<std::thread> workers;
    std::atomic<bool> running{false};

    void request_stop_from_runtime() {
        std::lock_guard<std::mutex> lock(mtx);
        running.store(false);
        status.running = false;
        status.message = "stopped by local runtime request";
        if (manager) manager->stop();
        if (io) io->stop();
    }
};

RuntimeController::RuntimeController()
    : impl_(std::make_unique<Impl>()) {}

RuntimeController::~RuntimeController() {
    stop();
}

bool RuntimeController::start(ServerConfig cfg, std::string* error) {
    if (error) error->clear();

    // Record the failure on impl_->status so a subsequent status() poll
    // returns it — without this, the GUI sees `running=false, message=""`
    // and the user has no idea why nothing happened.
    auto fail_with = [&](std::string msg) {
        if (error) *error = msg;
        std::lock_guard<std::mutex> lock(impl_->mtx);
        impl_->status.running = false;
        impl_->status.message = std::move(msg);
        return false;
    };

    if (privileged_port_requires_elevation(cfg.listen_port)) {
        return fail_with("listen port " + std::to_string(cfg.listen_port) +
                         " requires root or cap_net_bind_service");
    }

    {
        bool still_unwinding = false;
        {
            std::lock_guard<std::mutex> lock(impl_->mtx);
            if (impl_->running.load()) {
                return true;
            }
            still_unwinding = impl_->io || impl_->manager ||
                              !impl_->workers.empty();
        }
        if (still_unwinding) {
            return fail_with("server runtime is still stopping");
        }
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
    workers.reserve(static_cast<std::size_t>(workers_count));
    for (int i = 0; i < workers_count; ++i) {
        workers.emplace_back([raw = io.get()]() { raw->run(); });
    }

    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
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

    return true;
}

bool RuntimeController::stop() {
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

    if (local_runtime) local_runtime->stop();
    if (manager) manager->stop();
    if (io) io->stop();
    for (auto& worker : workers) {
        if (worker.joinable()) worker.join();
    }
    return true;
}

bool RuntimeController::running() const {
    return impl_->running.load();
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

bool RuntimeController::register_service(const std::string& service, std::string* error) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!impl_->manager) {
        if (error) *error = "server runtime is not running";
        return false;
    }
    return impl_->manager->register_service(service, error);
}

std::shared_ptr<runtime::ServiceStream> RuntimeController::accept_service_stream(
    const std::string& service,
    std::uint32_t timeout_ms,
    std::string* error) {
    std::shared_ptr<Manager> manager;
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        manager = impl_->manager;
    }
    if (!manager) {
        if (error) *error = "server runtime is not running";
        return {};
    }
    return manager->accept_service_stream(service, timeout_ms, error);
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
