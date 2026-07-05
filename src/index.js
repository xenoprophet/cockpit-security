const AUTO_REFRESH_MS = 15000;

const state = {
    firewallBackend: "ufw",
    securityLogSource: "all",
    firewallRules: {
        columns: [],
        rows: [],
        emptyText: "No rule data.",
        page: 1,
        pageSize: 10,
    },
    firewallDialog: {
        open: false,
        mode: "",
        busy: false,
        error: "",
    },
    currentJail: "",
    fail2banService: "fail2ban.service",
    autoRefreshTimer: null,
    refreshLocks: {
        firewall: null,
        fail2ban: null,
        logs: null,
    },
    securityLogsRefreshPending: false,
    toolInstalled: {
        ufw: null,
        iptables: null,
        fail2ban: null,
    },
    toolCommand: {
        ufw: "ufw",
        iptables: "iptables",
        fail2ban: "fail2ban-client",
    },
    installDialog: {
        open: false,
        toolId: "",
        packageNames: [],
        data: null,
        checking: false,
        busy: false,
        progressMessage: "",
        error: "",
        cancel: null,
    },
    superuserAllowed: null,
    superuserError: "",
    superuserProxy: null,
    superuserPermission: null,
    superuserDialog: {
        open: false,
        methods: [],
        selectedMethod: "",
        message: "",
        prompt: "",
        value: "",
        echo: false,
        error: "",
        errorTone: "warning",
        inProgress: false,
        promptSeen: false,
        cleanup: null,
        closeAfterSuccess: false,
    },
};

const SECURITY_LOG_FETCH_LIMIT = 200;
const SECURITY_LOG_DISPLAY_LIMIT = 10;

const SECURITY_LOG_SOURCES = [
    {
        id: "all",
        label: "All services",
        units: ["ufw.service", "iptables.service", "ip6tables.service", "netfilter-persistent.service", "nftables.service", "fail2ban.service"],
        kernelScope: "firewall",
    },
    {
        id: "ufw",
        label: "UFW",
        units: ["ufw.service"],
        kernelScope: "ufw",
    },
    {
        id: "iptables",
        label: "iptables",
        units: ["iptables.service", "ip6tables.service", "netfilter-persistent.service", "nftables.service"],
        kernelScope: "iptables",
    },
    {
        id: "fail2ban",
        label: "Fail2Ban",
        units: ["fail2ban.service"],
    },
];

const REQUIRED_TOOLS = {
    ufw: {
        id: "ufw",
        label: "UFW",
        command: "ufw",
        commands: ["ufw"],
        paths: ["/usr/sbin/ufw", "/sbin/ufw"],
        packages: ["ufw"],
        installTitle: "Install UFW",
        installCopy: "UFW must be installed to manage UFW firewall rules.",
    },
    iptables: {
        id: "iptables",
        label: "iptables",
        command: "iptables",
        commands: ["iptables", "iptables-nft", "iptables-legacy"],
        paths: ["/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables", "/usr/sbin/iptables-nft", "/usr/sbin/iptables-legacy"],
        packages: ["iptables"],
        packageCandidates: [["iptables"], ["iptables-nft"], ["iptables-services"]],
        installTitle: "Install iptables",
        installCopy: "iptables must be installed to manage iptables INPUT rules.",
    },
    fail2ban: {
        id: "fail2ban",
        label: "Fail2Ban",
        command: "fail2ban-client",
        commands: ["fail2ban-client"],
        paths: ["/usr/bin/fail2ban-client", "/usr/sbin/fail2ban-client"],
        packages: ["fail2ban"],
        packageCandidates: [["fail2ban"], ["fail2ban-server"]],
        installTitle: "Install Fail2Ban",
        installCopy: "Fail2Ban must be installed to view jail status and manage banned IPs.",
    },
};

const INSTALL_PROGRESS_TYPE = {
    DOWNLOADING: 0,
    UPDATING: 1,
    INSTALLING: 2,
    REMOVING: 3,
    REINSTALLING: 4,
    DOWNGRADING: 5,
};

const PACKAGEKIT_ENUM = {
    EXIT_SUCCESS: 1,
    EXIT_CANCELLED: 3,
    INFO_DOWNLOADING: 10,
    INFO_UPDATING: 11,
    INFO_INSTALLING: 12,
    INFO_REMOVING: 13,
    INFO_REINSTALLING: 19,
    INFO_DOWNGRADING: 20,
    STATUS_WAIT: 1,
    STATUS_WAITING_FOR_LOCK: 30,
    FILTER_NEWEST: (1 << 16),
    FILTER_ARCH: (1 << 18),
    FILTER_NOT_SOURCE: (1 << 21),
    TRANSACTION_FLAG_SIMULATE: (1 << 2),
};

const PACKAGEKIT_INSTALL_PROGRESS_MAP = {
    [PACKAGEKIT_ENUM.INFO_DOWNLOADING]: INSTALL_PROGRESS_TYPE.DOWNLOADING,
    [PACKAGEKIT_ENUM.INFO_UPDATING]: INSTALL_PROGRESS_TYPE.UPDATING,
    [PACKAGEKIT_ENUM.INFO_INSTALLING]: INSTALL_PROGRESS_TYPE.INSTALLING,
    [PACKAGEKIT_ENUM.INFO_REMOVING]: INSTALL_PROGRESS_TYPE.REMOVING,
    [PACKAGEKIT_ENUM.INFO_REINSTALLING]: INSTALL_PROGRESS_TYPE.REINSTALLING,
    [PACKAGEKIT_ENUM.INFO_DOWNGRADING]: INSTALL_PROGRESS_TYPE.DOWNGRADING,
};

const PACKAGEKIT_TRANSACTION_INTERFACE = "org.freedesktop.PackageKit.Transaction";
const SYSTEM_COMMAND_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const FAIL2BAN_SERVICE_CANDIDATES = ["fail2ban.service", "fail2ban-server.service"];
let packageManager = null;
let packageKitClient = null;
let dnf5Client = null;

function getElement(id) {
    return document.getElementById(id);
}

function setHidden(id, hidden) {
    const element = getElement(id);
    if (element)
        element.hidden = hidden;
}

function withRefreshLock(key, callback) {
    if (state.refreshLocks[key])
        return state.refreshLocks[key];

    const task = Promise.resolve()
        .then(callback)
        .finally(() => {
            state.refreshLocks[key] = null;
        });

    state.refreshLocks[key] = task;
    return task;
}

function stopAutoRefresh() {
    if (state.autoRefreshTimer) {
        window.clearInterval(state.autoRefreshTimer);
        state.autoRefreshTimer = null;
    }
}

function refreshSecurityPage() {
    if (state.superuserAllowed !== true)
        return Promise.resolve();

    return Promise.all([
        refreshFirewallStatus(),
        refreshFail2BanStatus(),
        refreshSecurityLogs(),
    ]);
}

function startAutoRefresh() {
    stopAutoRefresh();

    if (state.superuserAllowed !== true || document.hidden)
        return;

    state.autoRefreshTimer = window.setInterval(() => {
        if (document.hidden || state.superuserAllowed !== true)
            return;
        refreshSecurityPage();
    }, AUTO_REFRESH_MS);
}

function applyDarkMode(styleOverride) {
    const style = styleOverride || window.localStorage.getItem("shell:style") || "auto";
    const prefersDark = window.matchMedia?.("(prefers-color-scheme: dark)").matches;
    const darkMode = style === "dark" || (style === "auto" && prefersDark);
    document.documentElement.classList.toggle("pf-v6-theme-dark", darkMode);
}

function bindDarkMode() {
    applyDarkMode();

    window.addEventListener("storage", event => {
        if (event.key === "shell:style")
            applyDarkMode();
    });

    window.addEventListener("cockpit-style", event => {
        if (event instanceof CustomEvent)
            applyDarkMode(event.detail?.style);
    });

    const media = window.matchMedia?.("(prefers-color-scheme: dark)");
    media?.addEventListener?.("change", () => applyDarkMode());
}

function computeSuperuserAllowed() {
    if (!state.superuserProxy?.valid || state.superuserProxy.Current === "init")
        return null;

    return state.superuserProxy.Current !== "none";
}

function renderSuperuserDialog() {
    const dialog = getElement("security-auth-dialog");
    const alert = getElement("security-auth-alert");
    const title = getElement("security-auth-title");
    const message = getElement("security-auth-message");
    const methodField = getElement("security-auth-method-field");
    const methodSelect = getElement("security-auth-method");
    const promptField = getElement("security-auth-prompt-field");
    const promptLabel = getElement("security-auth-prompt-label");
    const promptInput = getElement("security-auth-input");
    const submit = getElement("security-auth-submit");
    const cancel = getElement("security-auth-cancel");

    if (!dialog || !alert || !title || !message || !methodField || !methodSelect || !promptField || !promptLabel || !promptInput || !submit || !cancel)
        return;

    const current = state.superuserDialog;
    dialog.hidden = !current.open;

    if (!current.open)
        return;

    title.textContent = "Switch to administrative access";

    alert.hidden = !current.error;
    alert.textContent = current.error;
    alert.classList.toggle("tone-danger", current.errorTone === "danger");

    methodField.hidden = current.methods.length <= 1 || Boolean(current.prompt);
    methodSelect.replaceChildren();
    current.methods.forEach(method => {
        const option = document.createElement("option");
        option.value = method.id;
        option.textContent = method.label;
        option.selected = method.id === current.selectedMethod;
        methodSelect.append(option);
    });
    methodSelect.disabled = current.inProgress;

    message.hidden = !current.message;
    message.textContent = current.message;

    promptField.hidden = !current.prompt;
    promptLabel.textContent = current.prompt || "Password";
    promptInput.type = current.echo ? "text" : "password";
    promptInput.value = current.value;
    promptInput.disabled = current.inProgress;

    submit.disabled = current.inProgress;
    cancel.disabled = current.inProgress;

    if (current.prompt)
        submit.textContent = current.inProgress ? "Authenticating..." : "Authenticate";
    else
        submit.textContent = current.inProgress ? "Authenticating..." : "Authenticate";

    window.setTimeout(() => {
        if (!state.superuserDialog.open)
            return;
        if (!promptField.hidden)
            promptInput.focus();
        else if (!methodField.hidden)
            methodSelect.focus();
        else
            submit.focus();
    }, 0);
}

function closeSuperuserDialog(options = {}) {
    if (options.stop !== false && state.superuserProxy?.valid)
        state.superuserProxy.Stop().catch(() => {});

    resetSuperuserDialog();
    renderSuperuserDialog();
}

function getPreferredSuperuserMethod(methods) {
    if (!methods.length)
        return "sudo";

    const sudo = methods.find(method => method.id === "sudo");
    return (sudo || methods[0]).id;
}

function updateSuperuserDialog(patch) {
    state.superuserDialog = {
        ...state.superuserDialog,
        ...patch,
    };
    renderSuperuserDialog();
}

async function invokeSuperuserStart(method) {
    try {
        return await state.superuserProxy.Start(method);
    } catch (error) {
        const message = formatError(error);
        if (/argument|signature|type/i.test(message))
            return state.superuserProxy.Start();
        throw error;
    }
}

async function startSuperuserAuthentication(method) {
    if (!state.superuserProxy?.valid || typeof state.superuserProxy.Start !== "function")
        throw new Error("This environment does not support enabling administrative access directly from this page.");

    const promptListener = (_event, message, prompt, value, _unused, echo, hintError) => {
        updateSuperuserDialog({
            message: normalizePromptText(message, "Authenticate to get administrative access"),
            prompt: normalizePromptText(prompt, "Password"),
            value: String(unwrapVariant(value) || ""),
            echo: Boolean(unwrapVariant(echo)),
            inProgress: false,
            error: hintError ? normalizePromptText(hintError) : "",
            errorTone: state.superuserDialog.promptSeen ? "danger" : "warning",
            promptSeen: true,
        });
    };

    updateSuperuserDialog({
        open: true,
        message: "Authenticate to get administrative access",
        prompt: "",
        value: "",
        echo: false,
        error: "",
        errorTone: "warning",
        inProgress: true,
        promptSeen: false,
    });

    state.superuserProxy.addEventListener("Prompt", promptListener);
    updateSuperuserDialog({
        cleanup: () => state.superuserProxy?.removeEventListener("Prompt", promptListener),
    });

    try {
        await invokeSuperuserStart(method);
        closeSuperuserDialog({ stop: false });
    } catch (error) {
        const message = formatError(error);
        if (message !== "cancelled") {
            updateSuperuserDialog({
                inProgress: false,
                prompt: "",
                message: "",
                error: normalizePromptText(message, "There was a problem switching to administrative access"),
                errorTone: "danger",
            });
        } else {
            closeSuperuserDialog();
        }
    }
}

async function handleSuperuserDialogSubmit(event) {
    event.preventDefault();
    const current = state.superuserDialog;
    if (!current.open || current.inProgress)
        return;

    if (current.prompt) {
        updateSuperuserDialog({
            inProgress: true,
            error: "",
        });
        state.superuserProxy?.Answer(current.value);
        return;
    }

    const methodSelect = getElement("security-auth-method");
    const selectedMethod = typeof methodSelect?.value === "string" && methodSelect.value
        ? methodSelect.value
        : getPreferredSuperuserMethod(current.methods);

    updateSuperuserDialog({
        selectedMethod,
    });
    await startSuperuserAuthentication(selectedMethod);
}

function handleSuperuserDialogInput(event) {
    if (event.target?.id === "security-auth-input") {
        updateSuperuserDialog({
            value: event.target.value,
        });
        return;
    }

    if (event.target?.id === "security-auth-method") {
        updateSuperuserDialog({
            selectedMethod: event.target.value,
        });
    }
}

async function requestSuperuserAccess() {
    if (state.superuserAllowed === true || state.superuserDialog.open)
        return;

    state.superuserError = "";
    renderAccessState();

    if (!state.superuserProxy?.valid || typeof state.superuserProxy.Start !== "function") {
        state.superuserError = " This environment does not support enabling administrative access directly from this page.";
        renderAccessState();
        return;
    }

    const methods = getSuperuserMethods();
    updateSuperuserDialog({
        open: true,
        methods,
        selectedMethod: getPreferredSuperuserMethod(methods),
        message: methods.length > 1 ? "" : "Authenticate to get administrative access",
        prompt: "",
        value: "",
        echo: false,
        error: "",
        errorTone: "warning",
        inProgress: false,
        promptSeen: false,
        cleanup: null,
    });

    await state.superuserProxy.Stop().catch(() => {});
    if (!state.superuserDialog.open)
        return;

    if (methods.length <= 1)
        await startSuperuserAuthentication(getPreferredSuperuserMethod(methods));
    else
        renderSuperuserDialog();
}

function renderAccessState() {
    const pageContent = document.querySelector(".page-content");
    const panel = getElement("security-access-panel");
    const title = getElement("security-access-title");
    const copy = getElement("security-access-copy");
    const action = getElement("security-access-action");
    const spinner = getElement("security-access-spinner");

    if (state.superuserAllowed === true) {
        if (panel)
            panel.classList.remove("is-loading");
        setHidden("security-access-panel", true);
        if (pageContent)
            pageContent.hidden = false;
        if (action)
            action.hidden = true;
        if (spinner)
            spinner.hidden = true;
        startAutoRefresh();
        return;
    }

    stopAutoRefresh();
    setHidden("security-access-panel", false);
    if (pageContent)
        pageContent.hidden = true;

    if (!title || !copy || !action)
        return;

    if (state.superuserAllowed === null) {
        if (panel)
            panel.classList.add("is-loading");
        if (spinner)
            spinner.hidden = false;
        title.textContent = "";
        copy.textContent = "";
        action.hidden = true;
        action.disabled = true;
        return;
    }

    if (panel)
        panel.classList.remove("is-loading");
    if (spinner)
        spinner.hidden = true;
    title.textContent = "Administrative access required";
    copy.textContent = state.superuserError
        ? `Administrative access is required to configure the firewall, manage Fail2Ban, and view security logs.${state.superuserError}`
        : "Administrative access is required to configure the firewall, manage Fail2Ban, and view security logs.";
    action.hidden = false;
    action.disabled = false;
    action.textContent = "Enable administrative access";
}

function handleSuperuserStateChange(nextAllowed) {
    const previous = state.superuserAllowed;
    state.superuserAllowed = nextAllowed;
    if (previous !== nextAllowed)
        resetDnf5Connection();
    if (nextAllowed !== false)
        state.superuserError = "";
    if (nextAllowed === true && state.superuserDialog.open)
        closeSuperuserDialog({ stop: false });
    renderAccessState();

    if (previous !== nextAllowed && nextAllowed === true)
        refreshSecurityPage();
}

function initSuperuser() {
    state.superuserProxy = cockpit.dbus(null, { bus: "internal" }).proxy("cockpit.Superuser", "/superuser");
    state.superuserProxy.addEventListener("changed", () => {
        handleSuperuserStateChange(computeSuperuserAllowed());
    });

    state.superuserProxy.wait(() => {
        if (!state.superuserProxy.valid) {
            state.superuserPermission = cockpit.permission({ admin: true });
            const updatePermission = () => {
                handleSuperuserStateChange(state.superuserPermission.allowed);
            };
            state.superuserPermission.addEventListener("changed", updatePermission);
            updatePermission();
            return;
        }

        handleSuperuserStateChange(computeSuperuserAllowed());
    });
}

function run(args) {
    return cockpit.spawn(args, {
        superuser: "require",
        err: "out",
        environ: [`PATH=${SYSTEM_COMMAND_PATH}`, "LC_ALL=C"],
    }).then(output => output.trim());
}

function runShell(script) {
    return run(["sh", "-lc", script]);
}

function capture(argsOrScript, options = {}) {
    const runner = options.shell ? runShell : run;
    return runner(argsOrScript)
        .then(output => ({ ok: true, output }))
        .catch(error => ({ ok: false, output: formatError(error) }));
}

function runUnprivileged(args) {
    return cockpit.spawn(args, {
        err: "out",
        environ: [`PATH=${SYSTEM_COMMAND_PATH}`, "LC_ALL=C"],
    }).then(output => output.trim());
}

function captureUnprivileged(args) {
    return runUnprivileged(args)
        .then(output => ({ ok: true, output }))
        .catch(error => ({ ok: false, output: formatError(error) }));
}

function getToolCommand(toolId) {
    return state.toolCommand[toolId] || REQUIRED_TOOLS[toolId]?.command || toolId;
}

async function checkToolInstalled(toolId, options = {}) {
    const tool = REQUIRED_TOOLS[toolId];
    if (!tool)
        return false;

    if (options.force !== true && state.toolInstalled[toolId] !== null)
        return state.toolInstalled[toolId];

    const commands = tool.commands || [tool.command];
    const paths = tool.paths || [];
    // Decide by the path we print, not by the script's exit status. cockpit.spawn's
    // resolve/reject behaviour around non-zero exits proved unreliable here (a missing
    // tool was still being treated as installed), and a login shell (-lc) can leak
    // /etc/profile output into stdout. Use a plain `sh -c` that always exits 0 and only
    // prints a path when the tool is actually found.
    const script = [
        `PATH=${SYSTEM_COMMAND_PATH}`,
        ...commands.map(command => `command -v ${command} 2>/dev/null && exit 0`),
        ...paths.map(path => `[ -x ${path} ] && echo ${path} && exit 0`),
        "exit 0",
    ].join("\n");
    const result = await captureUnprivileged(["sh", "-c", script]);
    const found = result.ok
        ? (result.output.split(/\r?\n/).map(line => line.trim()).find(Boolean) || "")
        : "";
    state.toolInstalled[toolId] = Boolean(found);
    if (found)
        state.toolCommand[toolId] = found;
    return Boolean(found);
}

function createPackageManagerError(name, message) {
    const error = new Error(message);
    error.name = name;
    return error;
}

async function isImmutableOS() {
    try {
        const options = await runUnprivileged(["findmnt", "-T", "/usr", "-n", "-o", "VFS-OPTIONS"]);
        return options.split(",").includes("ro");
    } catch (error) {
        console.debug("Unable to detect immutable OS", error);
        return false;
    }
}

async function detectDnf5Daemon() {
    const client = cockpit.dbus("org.rpm.dnf.v0", { superuser: "try" });
    let detected = false;

    try {
        await client.call("/org/rpm/dnf/v0", "org.freedesktop.DBus.Peer", "Ping", []);
        detected = true;
    } catch (error) {
        console.debug("dnf5daemon not supported", error);
    } finally {
        client.close();
    }

    return detected;
}

async function detectPackageKit() {
    const client = cockpit.dbus("org.freedesktop.PackageKit", { superuser: "try" });
    let detected = false;

    try {
        await client.call("/org/freedesktop/PackageKit", "org.freedesktop.DBus.Properties", "Get", ["org.freedesktop.PackageKit", "VersionMajor"]);
        detected = true;
    } catch (error) {
        console.debug("PackageKit not supported", error);
    } finally {
        client.close();
    }

    return detected;
}

async function getPackageManager(forcePackageKit = false) {
    if (packageManager !== null)
        return packageManager;

    const [unsupported, hasDnf5Daemon, hasPackageKit] = await Promise.all([
        isImmutableOS(),
        detectDnf5Daemon(),
        detectPackageKit(),
    ]);

    if (unsupported)
        throw createPackageManagerError("UnsupportedError", "Cockpit does not support installing additional packages on immutable operating systems");

    if (hasDnf5Daemon && !forcePackageKit) {
        packageManager = createDnf5DaemonManager();
        return packageManager;
    }

    if (hasPackageKit) {
        packageManager = createPackageKitManager();
        return packageManager;
    }

    throw createPackageManagerError("NotFoundError", "No package manager found");
}

function resetDnf5Connection() {
    if (dnf5Client)
        dnf5Client.close();
    dnf5Client = null;
}

function packageKitDbusClient() {
    if (!packageKitClient) {
        packageKitClient = cockpit.dbus("org.freedesktop.PackageKit", { superuser: "try", track: true });
        packageKitClient.addEventListener("close", () => {
            packageKitClient = null;
        });
    }

    return packageKitClient;
}

function packageKitCall(objectPath, iface, method, args, options) {
    return packageKitDbusClient().call(objectPath, iface, method, args, options);
}

function watchPackageKitTransaction(transactionPath, signalHandlers, notifyHandler) {
    const subscriptions = [];
    const client = packageKitDbusClient();

    function onClose(_event, error) {
        if (signalHandlers.ErrorCode)
            signalHandlers.ErrorCode("close", formatError(error) || "PackageKit disconnected.");
        if (signalHandlers.Finished)
            signalHandlers.Finished(PACKAGEKIT_ENUM.EXIT_CANCELLED);
    }

    function onNotify(reply) {
        const iface = reply?.detail?.[transactionPath]?.[PACKAGEKIT_TRANSACTION_INTERFACE];
        if (iface)
            notifyHandler(iface, transactionPath);
    }

    client.addEventListener("close", onClose);

    if (signalHandlers) {
        Object.keys(signalHandlers).forEach(handler => {
            subscriptions.push(client.subscribe({
                interface: PACKAGEKIT_TRANSACTION_INTERFACE,
                path: transactionPath,
                member: handler,
            }, (_path, _iface, _signal, args) => signalHandlers[handler](...args)));
        });
    }

    if (notifyHandler) {
        subscriptions.push(client.watch(transactionPath));
        client.addEventListener("notify", onNotify);
    }

    subscriptions.push(client.subscribe({
        interface: PACKAGEKIT_TRANSACTION_INTERFACE,
        path: transactionPath,
        member: "Finished",
    }, () => {
        subscriptions.forEach(subscription => subscription.remove());
        client.removeEventListener("close", onClose);
        if (notifyHandler)
            client.removeEventListener("notify", onNotify);
    }));

    return subscriptions[subscriptions.length - 1];
}

function packageKitTransaction(method, arglist, signalHandlers, notifyHandler) {
    return packageKitCall("/org/freedesktop/PackageKit", "org.freedesktop.PackageKit", "CreateTransaction", [])
        .then(([transactionPath]) => {
            if (!signalHandlers && !notifyHandler)
                return transactionPath;

            watchPackageKitTransaction(transactionPath, signalHandlers, notifyHandler);
            if (!method)
                return transactionPath;

            return packageKitCall(transactionPath, PACKAGEKIT_TRANSACTION_INTERFACE, method, arglist)
                .then(() => transactionPath);
        });
}

function packageKitCancellableTransaction(method, arglist, progressCallback, signalHandlers = {}) {
    return new Promise((resolve, reject) => {
        let cancelled = false;
        let status;
        let allowWaitStatus = false;
        const progressData = {
            waiting: false,
            percentage: 0,
            cancel: null,
        };

        function changed(props, transactionPath) {
            function cancel() {
                cancelled = true;
                packageKitCall(transactionPath, PACKAGEKIT_TRANSACTION_INTERFACE, "Cancel", []).catch(() => {});
            }

            if (!progressCallback)
                return;

            if ("Status" in props)
                status = props.Status;
            progressData.waiting = allowWaitStatus && (status === PACKAGEKIT_ENUM.STATUS_WAIT || status === PACKAGEKIT_ENUM.STATUS_WAITING_FOR_LOCK);
            if ("AllowCancel" in props)
                progressData.cancel = props.AllowCancel ? cancel : null;
            if ("Percentage" in props && props.Percentage <= 100)
                progressData.percentage = props.Percentage;

            progressCallback(progressData);
        }

        window.setTimeout(() => {
            allowWaitStatus = true;
            changed({});
        }, 1000);

        packageKitTransaction(method, arglist, {
            ...signalHandlers,
            ErrorCode: (code, detail) => {
                progressCallback = null;
                reject(new Error(cancelled ? "cancelled" : detail || code));
            },
            Finished: exit => {
                progressCallback = null;
                if (cancelled || exit === PACKAGEKIT_ENUM.EXIT_CANCELLED)
                    reject(new Error("cancelled"));
                else
                    resolve(exit);
            },
        }, changed).catch(error => {
            progressCallback = null;
            reject(error);
        });
    });
}

function packageProgressMessage(prefix, progress) {
    if (progress?.waiting)
        return "Waiting for another software management operation to finish";
    if (!progress?.package)
        return prefix;

    if (progress.info === INSTALL_PROGRESS_TYPE.DOWNLOADING)
        return `Downloading ${progress.package}`;
    if (progress.info === INSTALL_PROGRESS_TYPE.REMOVING)
        return `Removing ${progress.package}`;

    return `Installing ${progress.package}`;
}

function formatInstallError(error) {
    const message = formatError(error);
    if (/ServiceUnknown|not-found|not supported|No package manager/i.test(message))
        return "No software management service is available on this system, so packages cannot be installed from this page.";
    if (/immutable|read-only/i.test(message))
        return "This system does not support installing additional packages on an immutable /usr.";
    return message;
}

async function checkMissingPackages(packageNames, progressCallback) {
    const data = {
        download_size: 0,
        missing_ids: [],
        missing_names: [],
        unavailable_names: [],
        extra_names: [],
        remove_names: [],
    };

    await packageKitCancellableTransaction("RefreshCache", [false], progressCallback);

    const installedNames = new Set();
    await packageKitCancellableTransaction("Resolve", [
        PACKAGEKIT_ENUM.FILTER_ARCH | PACKAGEKIT_ENUM.FILTER_NOT_SOURCE | PACKAGEKIT_ENUM.FILTER_NEWEST,
        packageNames,
    ], progressCallback, {
        Package: (_info, packageId) => {
            const parts = packageId.split(";");
            const repos = parts[3]?.split(":") || [];
            if (repos.includes("installed")) {
                installedNames.add(parts[0]);
                return;
            }

            data.missing_ids.push(packageId);
            data.missing_names.push(parts[0]);
        },
    });

    packageNames.forEach(name => {
        if (!installedNames.has(name) && !data.missing_names.includes(name))
            data.unavailable_names.push(name);
    });

    if (data.missing_ids.length > 0 && data.unavailable_names.length === 0) {
        const installIds = [];
        await packageKitCancellableTransaction("InstallPackages", [
            PACKAGEKIT_ENUM.TRANSACTION_FLAG_SIMULATE,
            data.missing_ids,
        ], progressCallback, {
            Package: (info, packageId) => {
                const name = packageId.split(";")[0];
                if (info === PACKAGEKIT_ENUM.INFO_REMOVING) {
                    data.remove_names.push(name);
                } else if (info === PACKAGEKIT_ENUM.INFO_INSTALLING || info === PACKAGEKIT_ENUM.INFO_UPDATING) {
                    installIds.push(packageId);
                    if (!data.missing_names.includes(name))
                        data.extra_names.push(name);
                }
            },
        });

        if (installIds.length > 0) {
            await packageKitCancellableTransaction("GetDetails", [installIds], progressCallback, {
                Details: (...args) => {
                    const details = args[0];
                    const size = details?.size?.v || args[5]?.v || args[5];
                    if (Number.isFinite(Number(size)))
                        data.download_size += Number(size);
                },
            });
        }
    }

    data.missing_names.sort();
    data.extra_names.sort();
    data.remove_names.sort();
    return data;
}

async function installMissingPackages(data, progressCallback) {
    if (!data || data.missing_ids.length === 0)
        return;

    let lastProgress = null;
    let lastInfo = 0;
    let lastName = "";

    function reportProgress() {
        if (!lastProgress)
            return;

        progressCallback({
            waiting: lastProgress.waiting,
            percentage: lastProgress.percentage,
            cancel: lastProgress.cancel,
            info: PACKAGEKIT_INSTALL_PROGRESS_MAP[lastInfo],
            package: lastName,
        });
    }

    await packageKitCancellableTransaction("InstallPackages", [0, data.missing_ids], progress => {
        lastProgress = progress;
        reportProgress();
    }, {
        Package: (info, packageId) => {
            lastInfo = info;
            lastName = packageId.split(";")[0];
            reportProgress();
        },
    });
}

function createPackageKitManager() {
    return {
        name: "packagekit",
        check_missing_packages: checkMissingPackages,
        install_missing_packages: installMissingPackages,
    };
}

function dnf5DbusClient() {
    if (!dnf5Client) {
        dnf5Client = cockpit.dbus("org.rpm.dnf.v0", { superuser: "try", track: true });
        dnf5Client.addEventListener("close", () => {
            dnf5Client = null;
        });
    }

    return dnf5Client;
}

function dnf5Call(objectPath, iface, method, args, options) {
    return dnf5DbusClient().call(objectPath, iface, method, args, options);
}

async function openDnf5Session() {
    const [session] = await dnf5Call("/org/rpm/dnf/v0", "org.rpm.dnf.v0.SessionManager", "open_session", [{}]);
    return session;
}

function closeDnf5Session(session) {
    return dnf5Call("/org/rpm/dnf/v0", "org.rpm.dnf.v0.SessionManager", "close_session", [session]);
}

async function withDnf5Session(executor, signalHandler) {
    let session = null;
    let subscription = null;
    const client = dnf5DbusClient();

    if (signalHandler)
        subscription = client.subscribe({}, signalHandler);

    try {
        session = await openDnf5Session();
        return await executor(session);
    } finally {
        if (session)
            await closeDnf5Session(session);
        if (subscription)
            subscription.remove();
    }
}

function dnf5PackageName(pkg) {
    return pkg?.name?.v || "";
}

function createDnf5DaemonManager() {
    async function refresh(_force, _progressCallback) {
        await withDnf5Session(async session => {
            await dnf5Call(session, "org.rpm.dnf.v0.Base", "read_all_repos", []);
            const [, resolveResult] = await dnf5Call(session, "org.rpm.dnf.v0.Goal", "resolve", [{}]);
            if (resolveResult !== 0) {
                const [problem] = await dnf5Call(session, "org.rpm.dnf.v0.Goal", "get_transaction_problems_string", []);
                throw createPackageManagerError("ResolveError", `Resolving read_all_repos failed with result=${resolveResult} - ${problem}`);
            }
            await dnf5Call(session, "org.rpm.dnf.v0.Goal", "do_transaction", [{}]);
        });
    }

    async function checkMissingPackagesDnf5(packageNames, progressCallback) {
        const data = {
            download_size: 0,
            missing_ids: [],
            missing_names: [],
            unavailable_names: [],
            extra_names: [],
            remove_names: [],
        };

        if (packageNames.length === 0)
            return data;

        async function resolve(session) {
            const installedNames = new Set();
            const seenNames = new Set();
            const [results] = await dnf5Call(session, "org.rpm.dnf.v0.rpm.Rpm", "list", [{
                package_attrs: { t: "as", v: ["name", "is_installed"] },
                scope: { t: "s", v: "all" },
                patterns: { t: "as", v: packageNames },
            }]);

            for (const pkg of results || []) {
                const name = dnf5PackageName(pkg);
                if (!name || seenNames.has(name))
                    continue;

                if (pkg.is_installed?.v) {
                    installedNames.add(name);
                } else {
                    data.missing_ids.push(name);
                    data.missing_names.push(name);
                }

                seenNames.add(name);
            }

            packageNames.forEach(name => {
                if (!installedNames.has(name) && !data.missing_names.includes(name))
                    data.unavailable_names.push(name);
            });
        }

        async function simulate(session) {
            if (data.missing_ids.length === 0 || data.unavailable_names.length > 0)
                return;

            await dnf5Call(session, "org.rpm.dnf.v0.rpm.Rpm", "install", [packageNames, {}]);
            const [transactionItems, result] = await dnf5Call(session, "org.rpm.dnf.v0.Goal", "resolve", [{}]);
            if (result !== 0) {
                const [problem] = await dnf5Call(session, "org.rpm.dnf.v0.Goal", "get_transaction_problems_string", []);
                throw createPackageManagerError("ResolveError", `Resolving install failed with result=${result}. ${problem}`);
            }

            for (const transactionItem of transactionItems || []) {
                const [objectType, action, reason,, pkg] = transactionItem;
                const name = dnf5PackageName(pkg);
                if (objectType !== "Package" || !name)
                    continue;

                data.download_size += Number(pkg.download_size?.v || 0);
                if (reason === "Dependency" && !data.missing_names.includes(name))
                    data.extra_names.push(name);
                if (action === "Replaced" && !data.remove_names.includes(name))
                    data.remove_names.push(name);
            }

            await dnf5Call(session, "org.rpm.dnf.v0.Goal", "reset", []);
        }

        function signalEmitted() {
            if (progressCallback) {
                progressCallback({
                    waiting: false,
                    percentage: 0,
                    cancel: null,
                });
            }
        }

        await refresh(false);
        await withDnf5Session(async session => {
            await resolve(session);
            await simulate(session);
        }, signalEmitted);

        data.missing_names.sort();
        data.extra_names.sort();
        data.remove_names.sort();
        return data;
    }

    async function installMissingPackagesDnf5(data, progressCallback) {
        if (!data || data.missing_ids.length === 0)
            return;

        let lastInfo = INSTALL_PROGRESS_TYPE.INSTALLING;
        let lastProgress = 0;
        let lastName = "";
        let totalPackages = 0;

        function signalEmitted(_path, _iface, signal, args) {
            switch (signal) {
            case "download_add_new":
                lastInfo = INSTALL_PROGRESS_TYPE.DOWNLOADING;
                lastName = args[2] || "";
                break;
            case "download_progress":
                lastInfo = INSTALL_PROGRESS_TYPE.DOWNLOADING;
                break;
            case "download_end":
                lastInfo = INSTALL_PROGRESS_TYPE.INSTALLING;
                lastName = "";
                break;
            case "transaction_before_begin":
                totalPackages = Number(args[1] || 0);
                lastInfo = INSTALL_PROGRESS_TYPE.INSTALLING;
                break;
            case "transaction_elem_progress":
                lastName = args[1] || "";
                lastProgress = totalPackages ? Number(args[2] || 0) / totalPackages * 100 : 0;
                break;
            }

            if (progressCallback) {
                progressCallback({
                    cancel: null,
                    info: lastInfo,
                    package: lastName,
                    percentage: lastProgress,
                    waiting: false,
                });
            }
        }

        await withDnf5Session(async session => {
            try {
                await dnf5Call(session, "org.rpm.dnf.v0.rpm.Rpm", "install", [data.missing_names, {}]);
                const [, resolveResult] = await dnf5Call(session, "org.rpm.dnf.v0.Goal", "resolve", [{}]);
                if (resolveResult !== 0) {
                    const [problem] = await dnf5Call(session, "org.rpm.dnf.v0.Goal", "get_transaction_problems_string", []);
                    throw createPackageManagerError("ResolveError", `Resolving install failed with result=${resolveResult} ${problem}`);
                }
                await dnf5Call(session, "org.rpm.dnf.v0.Goal", "do_transaction", [{}]);
            } catch (error) {
                console.warn("install error", error);
            }
        }, signalEmitted);
    }

    return {
        name: "dnf5daemon",
        check_missing_packages: checkMissingPackagesDnf5,
        install_missing_packages: installMissingPackagesDnf5,
        refresh,
    };
}

function formatError(error) {
    if (typeof error === "string")
        return error;

    if (error?.message)
        return error.message;

    if (error?.problem)
        return `${error.problem}${error.exit_status ? ` (exit ${error.exit_status})` : ""}`;

    try {
        return JSON.stringify(error, null, 2);
    } catch (_error) {
        return "Command failed and the error object could not be parsed.";
    }
}

function unwrapVariant(value) {
    let current = value;
    while (
        current &&
        typeof current === "object" &&
        Object.prototype.hasOwnProperty.call(current, "v") &&
        Object.keys(current).length === 1
    ) {
        current = current.v;
    }
    return current;
}

function normalizePromptText(value, fallback = "") {
    const text = String(unwrapVariant(value) || "").replace(/^\[sudo] /, "").trim();
    if (!text)
        return fallback;
    return text.charAt(0).toUpperCase() + text.slice(1);
}

function getSuperuserMethods() {
    const methods = unwrapVariant(state.superuserProxy?.Methods);
    if (!methods || typeof methods !== "object")
        return [];

    return Object.keys(methods).map(id => {
        const definition = unwrapVariant(methods[id]);
        const label = normalizePromptText(unwrapVariant(definition?.label), id);
        return { id, label: label || id };
    });
}

function resetSuperuserDialog() {
    if (typeof state.superuserDialog.cleanup === "function")
        state.superuserDialog.cleanup();

    state.superuserDialog = {
        open: false,
        methods: [],
        selectedMethod: "",
        message: "",
        prompt: "",
        value: "",
        echo: false,
        error: "",
        errorTone: "warning",
        inProgress: false,
        promptSeen: false,
        cleanup: null,
        closeAfterSuccess: false,
    };
}

function setText(id, text) {
    const element = document.getElementById(id);
    if (element)
        element.textContent = text;
}

function setBadge(id, text, tone = "neutral") {
    const element = document.getElementById(id);
    if (!element)
        return;

    element.textContent = text;
    element.classList.remove("tone-success", "tone-warning", "tone-danger", "tone-loading", "pf-m-green", "pf-m-orange", "pf-m-red");
    if (tone === "success")
        element.classList.add("pf-m-green");
    else if (tone === "warning")
        element.classList.add("pf-m-orange");
    else if (tone === "danger")
        element.classList.add("pf-m-red");
    if (tone === "loading")
        element.classList.add("tone-loading");
}

function setCallout(id, text, tone = "neutral") {
    const element = document.getElementById(id);
    if (!element)
        return;

    element.textContent = text;
    element.hidden = !text;
    element.classList.remove("tone-success", "tone-warning", "tone-danger");
    if (tone === "success")
        element.classList.add("tone-success");
    else if (tone === "warning")
        element.classList.add("tone-warning");
    else if (tone === "danger")
        element.classList.add("tone-danger");
}

function getCurrentFirewallTool() {
    return REQUIRED_TOOLS[state.firewallBackend] || REQUIRED_TOOLS.ufw;
}

function renderFirewallInstallState(missing) {
    const tool = getCurrentFirewallTool();
    const content = getElement("firewall-settings-content");
    const installState = getElement("firewall-install-state");
    const title = getElement("firewall-install-title");
    const copy = getElement("firewall-install-copy");
    const action = getElement("firewall-install-action");

    if (content)
        content.hidden = Boolean(missing);
    if (installState)
        installState.hidden = !missing;

    if (!missing)
        return;

    setBadge("firewall-status-pill", "Not installed", "warning");
    if (title)
        title.textContent = tool.installTitle;
    if (copy)
        copy.textContent = tool.installCopy;
    if (action) {
        action.textContent = tool.installTitle;
        action.dataset.installTool = tool.id;
    }
}

function renderFail2BanInstallState(missing) {
    const content = getElement("fail2ban-settings-content");
    const installState = getElement("fail2ban-install-state");

    if (content)
        content.hidden = Boolean(missing);
    if (installState)
        installState.hidden = !missing;

    if (missing)
        setBadge("fail2ban-service-pill", "Not installed", "warning");
}

function resetInstallDialog(options = {}) {
    if (options.cancel !== false && typeof state.installDialog.cancel === "function")
        state.installDialog.cancel();

    state.installDialog = {
        open: false,
        toolId: "",
        packageNames: [],
        data: null,
        checking: false,
        busy: false,
        progressMessage: "",
        error: "",
        cancel: null,
    };
}

function updateInstallDialog(patch) {
    state.installDialog = {
        ...state.installDialog,
        ...patch,
    };
    renderInstallDialog();
}

function appendPackageList(container, label, items) {
    if (!items?.length)
        return;

    const section = document.createElement("div");
    section.className = "security-package-list";
    const heading = document.createElement("p");
    heading.textContent = label;
    const list = document.createElement("ul");
    list.className = "package-list-ct";

    items.forEach(item => {
        const listItem = document.createElement("li");
        listItem.textContent = item;
        list.append(listItem);
    });

    section.append(heading, list);
    container.append(section);
}

function renderInstallDialog() {
    const dialog = getElement("security-install-dialog");
    const title = getElement("security-install-title");
    const alert = getElement("security-install-alert");
    const body = getElement("security-install-body");
    const footerMessage = getElement("security-install-footer-message");
    const submit = getElement("security-install-submit");
    const cancel = getElement("security-install-cancel");
    const close = getElement("security-install-close");

    if (!dialog || !title || !alert || !body || !footerMessage || !submit || !cancel || !close)
        return;

    const current = state.installDialog;
    const tool = REQUIRED_TOOLS[current.toolId] || REQUIRED_TOOLS.ufw;
    dialog.hidden = !current.open;
    if (!current.open)
        return;

    title.textContent = "Install software";
    alert.hidden = !current.error;
    alert.textContent = current.error;
    alert.classList.toggle("tone-danger", Boolean(current.error));

    body.replaceChildren();
    const text = document.createElement("p");
    const packageNames = (current.packageNames?.length ? current.packageNames : tool.packages).join(", ");
    const packageName = document.createElement("strong");
    packageName.textContent = packageNames;
    text.append(packageName, " will be installed.");
    body.append(text);

    appendPackageList(body, "Additional packages:", current.data?.extra_names || []);
    appendPackageList(body, "Will be removed:", current.data?.remove_names || []);

    let footerText = current.progressMessage;
    if (!footerText && current.data?.download_size)
        footerText = `Total size: ${cockpit.format_bytes(current.data.download_size)}`;

    footerMessage.hidden = !footerText;
    footerMessage.replaceChildren();
    if (footerText) {
        footerMessage.append(document.createTextNode(footerText));
        if (current.checking || current.busy) {
            const spinner = document.createElement("span");
            spinner.className = "pf-v6-c-spinner pf-m-sm";
            spinner.setAttribute("role", "progressbar");
            spinner.setAttribute("aria-label", "Loading");
            footerMessage.append(spinner);
        }
    }

    submit.disabled = current.checking || current.busy || !current.data || Boolean(current.error && !current.data);
    submit.textContent = current.busy ? "Installing..." : "Install";
    cancel.disabled = false;
    close.disabled = false;
}

async function resolveToolInstallPackages(manager, tool, progressCallback) {
    const candidates = tool.packageCandidates?.length ? tool.packageCandidates : [tool.packages];
    let lastResult = null;
    const unavailableNames = new Set();

    for (const packageNames of candidates) {
        updateInstallDialog({ packageNames });
        const data = await manager.check_missing_packages(packageNames, progressCallback);
        lastResult = { packageNames, data };
        if (!data.unavailable_names.length)
            return lastResult;

        data.unavailable_names.forEach(name => unavailableNames.add(name));
    }

    if (lastResult && unavailableNames.size > 0)
        lastResult.data.unavailable_names = Array.from(unavailableNames);

    return lastResult;
}

async function openInstallDialog(toolId) {
    const tool = REQUIRED_TOOLS[toolId];
    if (!tool)
        return;

    if (await checkToolInstalled(toolId, { force: true })) {
        if (toolId === "fail2ban")
            refreshFail2BanStatus();
        else
            refreshFirewallStatus();
        return;
    }

    resetInstallDialog();
    state.installDialog = {
        open: true,
        toolId,
        packageNames: tool.packages,
        data: null,
        checking: true,
        busy: false,
        progressMessage: "Checking installed software",
        error: "",
        cancel: null,
    };
    renderInstallDialog();

    try {
        const manager = await getPackageManager();
        const result = await resolveToolInstallPackages(manager, tool, progress => {
            updateInstallDialog({
                progressMessage: progress?.waiting ? "Waiting for another software management operation to finish" : "Checking installed software",
                cancel: progress?.cancel || null,
            });
        });
        const data = result?.data || { unavailable_names: tool.packages };

        updateInstallDialog({
            packageNames: result?.packageNames || tool.packages,
            data: data.unavailable_names.length ? null : data,
            checking: false,
            progressMessage: "",
            cancel: null,
            error: data.unavailable_names.length
                ? `${data.unavailable_names[0]}  is not in any available software repository.`
                : "",
        });
    } catch (error) {
        if (formatError(error) === "cancelled") {
            closeInstallDialog();
            return;
        }

        updateInstallDialog({
            checking: false,
            progressMessage: "",
            cancel: null,
            error: formatInstallError(error) || "Unable to use the system software management service.",
        });
    }
}

function closeInstallDialog(options = {}) {
    resetInstallDialog(options);
    renderInstallDialog();
}

async function handleInstallDialogSubmit() {
    const current = state.installDialog;
    if (!current.open || current.checking || current.busy || !current.data)
        return;

    const toolId = current.toolId;
    updateInstallDialog({
        busy: true,
        error: "",
        progressMessage: "Installing packages",
    });

    try {
        const manager = await getPackageManager();
        await manager.install_missing_packages(current.data, progress => {
            updateInstallDialog({
                progressMessage: packageProgressMessage("Installing packages", progress),
                cancel: progress?.cancel || null,
            });
        });
    } catch (error) {
        if (formatError(error) === "cancelled") {
            closeInstallDialog();
            return;
        }

        updateInstallDialog({
            busy: false,
            progressMessage: "",
            cancel: null,
            error: formatInstallError(error) || "Failed to install packages.",
        });
        return;
    }

    closeInstallDialog({ cancel: false });
    await checkToolInstalled(toolId, { force: true });
    if (toolId === "fail2ban")
        await refreshFail2BanStatus();
    else
        await refreshFirewallStatus();
    refreshSecurityLogs();
}

function summarizeOutput(text, ok = true) {
    const lines = String(text || "")
        .split(/\r?\n/)
        .map(line => line.trim())
        .filter(Boolean);

    if (!lines.length)
        return ok ? "Command completed with no additional output." : "Command failed.";

    const combined = lines.join(" ");
    if (/permission denied to socket/i.test(combined))
        return "Administrative access is required to access the Fail2Ban socket.";

    if (/you must be root/i.test(combined))
        return "This command requires root privileges.";

    if (/not found|command not found|No such file/i.test(combined))
        return "The command or related component was not found. Make sure it is installed on the target host.";

    return lines[0];
}

function renderDetailList(id, items, emptyText = "No details.") {
    const list = document.getElementById(id);
    if (!list)
        return;

    list.replaceChildren();

    const entries = items.length ? items : [["Status", emptyText]];
    const fragment = document.createDocumentFragment();

    entries.forEach(([label, value]) => {
        const group = document.createElement("div");
        group.className = "pf-v6-c-description-list__group";

        const dt = document.createElement("dt");
        dt.className = "pf-v6-c-description-list__term";
        const termText = document.createElement("span");
        termText.className = "pf-v6-c-description-list__text";
        termText.textContent = label;
        dt.append(termText);

        const dd = document.createElement("dd");
        dd.className = "pf-v6-c-description-list__description";
        const descriptionText = document.createElement("div");
        descriptionText.className = "pf-v6-c-description-list__text";
        descriptionText.textContent = value;
        dd.append(descriptionText);

        group.append(dt, dd);
        fragment.append(group);
    });

    list.append(fragment);
}

function renderTable(headId, bodyId, emptyId, columns, rows, emptyText) {
    const head = document.getElementById(headId);
    const body = document.getElementById(bodyId);
    const empty = document.getElementById(emptyId);

    if (!head || !body || !empty)
        return;

    const normalizedRows = rows.map(row => Array.isArray(row) ? { cells: row } : row);
    const hasActions = normalizedRows.some(row => row.delete);
    const table = body.closest("table");
    const headRow = document.createElement("tr");
    headRow.className = "pf-v6-c-table__tr";
    columns.forEach(column => {
        const th = document.createElement("th");
        th.className = "pf-v6-c-table__th";
        th.scope = "col";
        th.textContent = column;
        headRow.append(th);
    });
    if (hasActions) {
        const th = document.createElement("th");
        th.className = "pf-v6-c-table__th";
        th.scope = "col";
        th.textContent = "Actions";
        headRow.append(th);
    }

    head.replaceChildren(headRow);
    body.replaceChildren();
    table?.classList.toggle("ct-table-empty", !normalizedRows.length);

    if (!normalizedRows.length) {
        empty.hidden = true;
        const row = document.createElement("tr");
        row.className = "pf-v6-c-table__tr";
        const cell = document.createElement("td");
        cell.className = "pf-v6-c-table__td empty-message";
        cell.colSpan = columns.length + (hasActions ? 1 : 0);
        cell.textContent = emptyText;
        row.append(cell);
        body.append(row);
        return;
    }

    empty.hidden = true;
    normalizedRows.forEach(row => {
        const tr = document.createElement("tr");
        tr.className = "pf-v6-c-table__tr";

        row.cells.forEach((cell, index) => {
            const element = document.createElement(index === 0 ? "th" : "td");
            if (index === 0) {
                element.scope = "row";
                element.className = "pf-v6-c-table__th data-table__primary";
            } else {
                element.className = "pf-v6-c-table__td";
            }
            element.dataset.label = columns[index] || "";
            element.textContent = cell;
            tr.append(element);
        });

        if (hasActions) {
            const actionCell = document.createElement("td");
            actionCell.className = "pf-v6-c-table__td data-table__action";
            actionCell.dataset.label = "Actions";

            if (row.delete) {
                const button = document.createElement("button");
                button.type = "button";
                button.className = "pf-v6-c-button pf-m-link pf-m-inline data-table__delete";
                button.textContent = row.delete.label || "Delete";
                button.addEventListener("click", () => {
                    deleteFirewallRule(row.delete);
                });
                actionCell.append(button);
            }

            tr.append(actionCell);
        }

        body.append(tr);
    });
}

function getFirewallRuleTotalPages() {
    return Math.max(1, Math.ceil(state.firewallRules.rows.length / state.firewallRules.pageSize));
}

function updateFirewallRulePageOptions(totalPages) {
    const options = document.getElementById("firewall-rules-page-options");
    if (!options)
        return;

    const fragment = document.createDocumentFragment();
    for (let page = 1; page <= totalPages; page++) {
        const option = document.createElement("option");
        option.value = String(page);
        option.label = `Page ${page}`;
        fragment.append(option);
    }
    options.replaceChildren(fragment);
}

function renderFirewallRulePagination(totalRows) {
    const container = document.getElementById("firewall-rules-pagination");
    const meta = document.getElementById("firewall-rules-page-meta");
    const prev = document.getElementById("firewall-rules-prev");
    const next = document.getElementById("firewall-rules-next");
    const jumpInput = document.getElementById("firewall-rules-page-jump");

    if (!container || !meta || !prev || !next)
        return;

    const totalPages = Math.max(1, Math.ceil(totalRows / state.firewallRules.pageSize));
    container.hidden = totalRows <= state.firewallRules.pageSize;
    meta.textContent = `Page ${state.firewallRules.page} / ${totalPages}`;
    prev.disabled = state.firewallRules.page <= 1;
    next.disabled = state.firewallRules.page >= totalPages;
    updateFirewallRulePageOptions(totalPages);

    if (jumpInput) {
        jumpInput.value = String(state.firewallRules.page);
        jumpInput.setAttribute("aria-label", `Go to page, total ${totalPages}`);
    }
}

function renderFirewallRulesTable() {
    const { columns, rows, emptyText, page, pageSize } = state.firewallRules;
    const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
    const currentPage = Math.min(Math.max(1, page), totalPages);
    state.firewallRules.page = currentPage;

    const start = (currentPage - 1) * pageSize;
    const pageRows = rows.slice(start, start + pageSize);
    renderTable("firewall-rules-head", "firewall-rules-body", "firewall-rules-empty", columns, pageRows, emptyText);
    renderFirewallRulePagination(rows.length);
}

function jumpToFirewallRulesPage(value) {
    const pageText = String(value || "").trim();
    if (!/^\d+$/.test(pageText)) {
        renderFirewallRulesTable();
        return;
    }

    const totalPages = getFirewallRuleTotalPages();
    const nextPage = Math.min(Math.max(1, Number(pageText)), totalPages);
    state.firewallRules.page = nextPage;
    renderFirewallRulesTable();
}

function renderMetricCards(id, metrics) {
    const container = document.getElementById(id);
    if (!container)
        return;

    container.replaceChildren();

    if (!metrics.length) {
        const card = document.createElement("div");
        card.className = "metric-card";
        const label = document.createElement("span");
        label.textContent = "Jail";
        const value = document.createElement("strong");
        value.textContent = "No data";
        card.append(label, value);
        container.append(card);
        return;
    }

    metrics.forEach(metric => {
        const card = document.createElement("div");
        card.className = "metric-card";
        const label = document.createElement("span");
        label.textContent = metric.label;
        const value = document.createElement("strong");
        value.textContent = metric.value;
        card.append(label, value);
        container.append(card);
    });
}

function renderTokenRow(id, items, options = {}) {
    const container = document.getElementById(id);
    if (!container)
        return;

    container.replaceChildren();

    if (!items.length && options.emptyText) {
        const token = document.createElement("span");
        token.className = "pf-v6-c-label pf-m-outline token";
        token.textContent = options.emptyText;
        container.append(token);
        return;
    }

    items.forEach(item => {
        if (options.clickable) {
            const button = document.createElement("button");
            button.type = "button";
            button.className = "pf-v6-c-button pf-m-tertiary token-button";
            button.textContent = item;
            button.addEventListener("click", () => options.onClick(item));
            container.append(button);
            return;
        }

        const token = document.createElement("span");
        token.className = "pf-v6-c-label pf-m-outline token";
        token.textContent = item;
        container.append(token);
    });
}

function getSecurityLogSource(id = state.securityLogSource) {
    return SECURITY_LOG_SOURCES.find(source => source.id === id) || SECURITY_LOG_SOURCES[0];
}

function renderSecurityLogSourceOptions() {
    const menuList = document.getElementById("security-log-menu-list");
    const toggleText = document.getElementById("security-log-source-text");
    if (!menuList || !toggleText)
        return;

    const currentSource = getSecurityLogSource();
    toggleText.textContent = currentSource.label;

    menuList.replaceChildren();
    SECURITY_LOG_SOURCES.forEach(source => {
        const item = document.createElement("li");
        item.setAttribute("role", "menuitem");
        item.className = "pf-v6-c-menu__item";
        if (source.id === state.securityLogSource)
            item.classList.add("pf-m-selected");
        item.textContent = source.label;

        const button = document.createElement("button");
        button.type = "button";
        button.className = "pf-v6-c-menu__item";
        if (source.id === state.securityLogSource)
            button.classList.add("pf-m-selected");
        button.textContent = source.label;
        button.addEventListener("click", () => {
            switchSecurityLogSource(source.id);
            closeSecurityLogMenu();
        });

        const listItem = document.createElement("li");
        listItem.setAttribute("role", "none");
        listItem.append(button);
        menuList.append(listItem);
    });
}

function toggleSecurityLogMenu() {
    const menu = document.getElementById("security-log-menu");
    if (!menu)
        return;
    menu.hidden = !menu.hidden;
}

function closeSecurityLogMenu() {
    const menu = document.getElementById("security-log-menu");
    if (menu)
        menu.hidden = true;
}

function buildSecurityLogArgs(source = getSecurityLogSource()) {
    const args = ["journalctl", "-q", "--no-pager", "-n", String(SECURITY_LOG_FETCH_LIMIT), "-o", "json"];
    let hasMatch = false;

    source.units.forEach(unit => {
        if (hasMatch)
            args.push("+");
        args.push(`_SYSTEMD_UNIT=${unit}`);
        hasMatch = true;
    });

    if (source.kernelScope) {
        if (hasMatch)
            args.push("+");
        args.push("_TRANSPORT=kernel");
    }

    return args;
}

function getSecurityLogUrl(source = getSecurityLogSource()) {
    const params = new URLSearchParams({ prio: "debug" });
    if (source.units.length)
        params.set("_SYSTEMD_UNIT", source.units.join(","));
    if (source.kernelScope)
        params.set("_TRANSPORT", "kernel");

    return `/system/logs/#/?${params.toString()}`;
}

function getSecurityLogParentOptions(source = getSecurityLogSource()) {
    const options = { prio: "debug" };
    if (source.units.length)
        options._SYSTEMD_UNIT = source.units.join(",");
    if (source.kernelScope)
        options._TRANSPORT = "kernel";
    return options;
}

function isKernelJournalEntry(entry) {
    return entry._TRANSPORT === "kernel" || entry.SYSLOG_IDENTIFIER === "kernel" || entry._COMM === "kernel";
}

function isUfwKernelMessage(message) {
    return /\bUFW\b|\[UFW\s+/i.test(message);
}

function isFirewallKernelMessage(message) {
    const normalized = normalizeWhitespace(message);
    return isUfwKernelMessage(normalized) ||
        /\b(?:IN|OUT|MAC|SRC|DST|LEN|TOS|PREC|TTL|ID|PROTO|SPT|DPT|WINDOW|RES|UID|GID)=/i.test(normalized) ||
        /\b(?:iptables|ip6tables|nftables|netfilter)\b/i.test(normalized);
}

function entryMatchesSecurityLogSource(entry, source = getSecurityLogSource()) {
    if (source.units.includes(entry._SYSTEMD_UNIT))
        return true;

    if (!source.kernelScope || !isKernelJournalEntry(entry))
        return false;

    const message = getJournalMessage(entry);
    if (source.kernelScope === "ufw")
        return isUfwKernelMessage(message);
    if (source.kernelScope === "iptables")
        return isFirewallKernelMessage(message) && !isUfwKernelMessage(message);

    return isFirewallKernelMessage(message);
}

function formatJournalTimestamp(entry, options) {
    const timestamp = Number(entry.__REALTIME_TIMESTAMP);
    if (!Number.isFinite(timestamp))
        return "";

    return new Date(timestamp / 1000).toLocaleString("en-US", options);
}

function formatJournalDay(entry) {
    return formatJournalTimestamp(entry, {
        year: "numeric",
        month: "long",
        day: "numeric",
    });
}

function formatJournalTime(entry) {
    return formatJournalTimestamp(entry, {
        hour: "2-digit",
        minute: "2-digit",
    });
}

function getJournalIdentifier(entry) {
    return entry.SYSLOG_IDENTIFIER || entry._COMM || entry._SYSTEMD_UNIT || "journal";
}

function getJournalMessage(entry) {
    return String(entry.MESSAGE || "").trim() || "No log message.";
}

function openJournalEntry(entry) {
    if (!entry.__CURSOR)
        return;

    const parentOptions = encodeURIComponent(JSON.stringify(getSecurityLogParentOptions()));
    cockpit.jump(`system/logs#/${entry.__CURSOR}?parent_options=${parentOptions}`);
}

function getSecurityLogContainer() {
    return document.getElementById("security-log-list");
}

function renderSecurityLogs(entries) {
    const container = getSecurityLogContainer();
    if (!container)
        return;

    container.replaceChildren();

    if (!entries.length) {
        const empty = document.createElement("div");
        empty.className = "empty-message";
        empty.textContent = "No security logs.";
        container.append(empty);
        return;
    }

    let currentDay = "";
    entries.forEach(entry => {
        const day = formatJournalDay(entry);
        if (day && day !== currentDay) {
            currentDay = day;
            const heading = document.createElement("div");
            heading.className = "panel-heading";
            heading.textContent = day;
            container.append(heading);
        }

        const row = document.createElement("div");
        row.className = "cockpit-logline";
        row.role = "row";
        row.tabIndex = 0;
        row.addEventListener("click", () => openJournalEntry(entry));
        row.addEventListener("keydown", event => {
            if (event.key === "Enter")
                openJournalEntry(entry);
        });

        const warning = document.createElement("div");
        warning.className = "cockpit-log-warning";
        warning.role = "cell";
        warning.textContent = Number(entry.PRIORITY) < 4 ? "!" : "";

        const time = document.createElement("div");
        time.className = "cockpit-log-time";
        time.role = "cell";
        time.textContent = formatJournalTime(entry);

        const message = document.createElement("span");
        message.className = "cockpit-log-message";
        message.role = "cell";
        message.textContent = getJournalMessage(entry);

        const service = document.createElement("div");
        service.className = "cockpit-log-service";
        service.role = "cell";
        service.textContent = getJournalIdentifier(entry);

        row.append(warning, time, message, service);
        container.append(row);
    });
}

function renderSecurityLogMessage(message) {
    const container = getSecurityLogContainer();
    if (!container)
        return;

    const empty = document.createElement("div");
    empty.className = "empty-message";
    empty.textContent = message;
    container.replaceChildren(empty);
}

async function refreshSecurityLogs() {
    if (state.refreshLocks.logs) {
        state.securityLogsRefreshPending = true;
        renderSecurityLogMessage("Loading security logs...");
        return state.refreshLocks.logs;
    }

    const task = withRefreshLock("logs", async () => {
        if (state.superuserAllowed !== true)
            return;

        const sourceId = state.securityLogSource;
        const source = getSecurityLogSource();
        renderSecurityLogMessage("Loading security logs...");
        const result = await capture(buildSecurityLogArgs(source));
        if (state.securityLogSource !== sourceId) {
            state.securityLogsRefreshPending = true;
            return;
        }

        if (!result.ok) {
            renderSecurityLogMessage(summarizeOutput(result.output, false));
            return;
        }

        const entries = String(result.output || "")
            .split(/\r?\n/)
            .map(line => line.trim())
            .filter(Boolean)
            .map(line => {
                try {
                    return JSON.parse(line);
                } catch (_error) {
                    return null;
                }
            })
            .filter(Boolean)
            .filter(entry => entryMatchesSecurityLogSource(entry, source))
            .slice(-SECURITY_LOG_DISPLAY_LIMIT);

        renderSecurityLogs(entries);
    });

    return task.finally(() => {
        if (state.securityLogsRefreshPending && state.superuserAllowed === true) {
            state.securityLogsRefreshPending = false;
            return refreshSecurityLogs();
        }
    });
}

function switchSecurityLogSource(sourceId) {
    state.securityLogSource = sourceId;
    renderSecurityLogSourceOptions();
    refreshSecurityLogs();
}

function positionSecurityLogMenu() {
    const toggle = document.getElementById("security-log-source-toggle");
    const menu = document.getElementById("security-log-menu");
    if (!toggle || !menu)
        return;
    const rect = toggle.getBoundingClientRect();
    menu.style.position = "fixed";
    menu.style.top = (rect.bottom + 4) + "px";
    menu.style.left = rect.left + "px";
    menu.style.minWidth = rect.width + "px";
}

function normalizeStatus(value) {
    const normalized = String(value || "").trim().toLowerCase();
    const mapping = {
        active: "Running",
        inactive: "Not running",
        running: "Running",
        failed: "Failed",
        enabled: "Enabled",
        disabled: "Disabled",
        loaded: "Loaded",
        masked: "Masked",
    };
    return mapping[normalized] || value || "Unknown";
}

function normalizeWhitespace(value) {
    return String(value || "").replace(/\s+/g, " ").trim();
}

function parseSystemdShow(output) {
    const values = {};
    String(output || "").split(/\r?\n/).forEach(line => {
        const index = line.indexOf("=");
        if (index <= 0)
            return;

        values[line.slice(0, index)] = line.slice(index + 1).trim();
    });
    return values;
}

async function resolveServiceUnit(candidates, fallback) {
    for (const candidate of candidates) {
        const result = await capture(["systemctl", "show", candidate, "--property=LoadState", "--value"], { updateResult: false });
        if (result.ok && String(result.output || "").trim() !== "not-found")
            return candidate;
    }

    return fallback;
}

async function resolveFail2BanService() {
    state.fail2banService = await resolveServiceUnit(FAIL2BAN_SERVICE_CANDIDATES, "fail2ban.service");
    return state.fail2banService;
}

function parseUfwStatus(numberedOutput, verboseOutput) {
    const rules = [];
    String(numberedOutput || "").split(/\r?\n/).forEach(line => {
        const match = line.match(/^\[\s*(\d+)\]\s+(.+?)\s{2,}(\S+)\s+(\S+)\s+(.+)$/);
        if (!match)
            return;

        rules.push({
            number: match[1],
            to: match[2].trim(),
            action: match[3],
            direction: match[4],
            from: match[5].trim(),
        });
    });

    const sourceText = verboseOutput || numberedOutput;
    const status = sourceText.match(/Status:\s*(.+)/i)?.[1]?.trim() || "unknown";
    const defaults = sourceText.match(/Default:\s*(.+)/i)?.[1]?.trim() || "";
    const logging = sourceText.match(/Logging:\s*(.+)/i)?.[1]?.trim() || "";
    const isActive = status.toLowerCase() === "active";

    return {
        summary: isActive
            ? `UFW is enabled, parsed ${rules.length} rules.`
            : "UFW is not currently enabled.",
        statusLabel: isActive ? "Running" : normalizeStatus(status),
        tone: isActive ? "success" : "warning",
        ruleCount: String(rules.length),
        policySummary: defaults ? `Default policy: ${defaults}` : "No default policy was parsed.",
        details: [
            ["Status", normalizeStatus(status)],
            defaults ? ["Default policy", defaults] : null,
            logging ? ["Logging", logging] : null,
            ["Rule count", String(rules.length)],
        ].filter(Boolean),
        columns: ["Number", "To", "Action", "Direction", "Source"],
        rows: rules.map(rule => ({
            cells: [rule.number, rule.to, rule.action, rule.direction, rule.from],
            delete: {
                kind: "ufw",
                value: rule.number,
                label: "Delete",
            },
        })),
        emptyText: isActive ? "There are no UFW rules." : "UFW is not enabled, so no rules can be displayed.",
    };
}

function parseIptablesStatus(listOutput) {
    const lines = String(listOutput || "").split(/\r?\n/);
    const chainLine = lines.find(line => /^Chain\s+INPUT/i.test(line));
    const policy = chainLine?.match(/\(policy\s+([A-Z]+)/)?.[1] || "Unknown";
    const rules = [];
    let tableStarted = false;

    lines.forEach(line => {
        const trimmed = line.trim();
        if (!trimmed)
            return;

        if (/^num\s+pkts\s+bytes/i.test(trimmed)) {
            tableStarted = true;
            return;
        }

        if (!tableStarted)
            return;

        const parts = trimmed.split(/\s+/);
        if (parts.length < 10)
            return;

        const [num, pkts, bytes, target, protocol, opt, inputIf, outputIf, source, destination, ...rest] = parts;
        rules.push({
            num,
            pkts,
            bytes,
            target,
            protocol,
            inputIf,
            outputIf,
            source,
            destination,
            detail: rest.join(" "),
            opt,
        });
    });

    return {
        summary: `The INPUT chain default policy is ${policy}, parsed ${rules.length} rules.`,
        statusLabel: `Policy ${policy}`,
        tone: policy === "DROP" ? "warning" : "success",
        ruleCount: String(rules.length),
        policySummary: `Default policy: ${policy}`,
        details: [
            ["Chain", "INPUT"],
            ["Default policy", policy],
            ["Rule count", String(rules.length)],
        ],
        columns: ["Line", "To", "Protocol", "Source", "Destination", "Match"],
        rows: rules.map(rule => ({
            cells: [
                rule.num,
                rule.target,
                rule.protocol,
                rule.source,
                rule.destination,
                normalizeWhitespace(rule.detail || rule.opt),
            ],
            delete: {
                kind: "iptables",
                value: rule.num,
                label: "Delete",
            },
        })),
        emptyText: "There are no iptables INPUT rules.",
    };
}

function parseFail2BanOverview(serviceOutput, statusOutput, serviceOk, statusOk) {
    const service = parseSystemdShow(serviceOutput);
    const jailCountMatch = statusOutput.match(/Number of jail:\s*(\d+)/i);
    const jailListMatch = statusOutput.match(/Jail list:\s*(.+)/i);
    const jailCount = jailCountMatch ? Number(jailCountMatch[1]) : 0;
    const jails = jailListMatch
        ? jailListMatch[1].split(",").map(item => item.trim()).filter(Boolean)
        : [];
    const activeState = service.ActiveState || "";
    const serviceState = activeState ? `${normalizeStatus(activeState)} / ${service.SubState || "unknown"}` : "Unknown";

    let summary = "No Fail2Ban status was returned.";
    let tone = "warning";

    if (serviceOk && statusOk) {
        summary = jails.length
            ? `There are ${jails.length} jails: ${jails.join(", ")}.`
            : "There are no enabled jails.";
        tone = activeState === "active" ? "success" : "warning";
    } else if (/permission denied|must be root/i.test(statusOutput)) {
        summary = "The Fail2Ban socket requires administrative access, which this session does not have.";
    } else if (!statusOk) {
        summary = summarizeOutput(statusOutput, false);
        tone = "danger";
    }

    return {
        jailCount,
        jails,
        serviceState,
        summary,
        tone,
        details: [
            ["Service", service.Id || "fail2ban.service"],
            service.Description ? ["Description", service.Description] : null,
            service.ActiveState ? ["Runtime state", normalizeStatus(service.ActiveState)] : null,
            service.SubState ? ["Substate", service.SubState] : null,
            service.UnitFileState ? ["Boot policy", normalizeStatus(service.UnitFileState)] : null,
            service.LoadState ? ["Load state", normalizeStatus(service.LoadState)] : null,
            ["Jail count", String(jailCount)],
            jails.length ? ["Jail list", jails.join(", ")] : null,
        ].filter(Boolean),
    };
}

function parseFail2BanJail(output, jailName) {
    const detailMap = {};
    String(output || "").split(/\r?\n/).forEach(line => {
        const cleaned = line.replace(/^[\s|`-]+/, "").trim();
        if (!cleaned.includes(":"))
            return;

        const index = cleaned.indexOf(":");
        const key = cleaned.slice(0, index).trim();
        const value = cleaned.slice(index + 1).trim();
        if (key)
            detailMap[key] = value;
    });

    const bannedIps = (detailMap["Banned IP list"] || "")
        .split(/\s+/)
        .map(item => item.trim())
        .filter(Boolean);

    return {
        name: output.match(/Status for the jail:\s*(.+)/i)?.[1]?.trim() || jailName,
        metrics: [
            { label: "Currently failed", value: detailMap["Currently failed"] || "0" },
            { label: "Currently banned", value: detailMap["Currently banned"] || "0" },
            { label: "Total banned", value: detailMap["Total banned"] || "0" },
        ],
        details: [
            ["Total failed", detailMap["Total failed"] || "0"],
            detailMap["File list"] ? ["Log files", detailMap["File list"]] : null,
            detailMap["Banned IP list"] ? ["Banned IPs", detailMap["Banned IP list"]] : null,
        ].filter(Boolean),
        bannedIps,
        summary: `Loaded jail ${jailName}, currently banned ${detailMap["Currently banned"] || "0"} IPs.`,
    };
}

function renderFirewallStatus(parsed) {
    renderFirewallInstallState(false);
    setText("firewall-backend-label", getCurrentFirewallTool().label);
    setText("firewall-summary-copy", parsed.summary);
    setText("firewall-policy-summary", parsed.policySummary);
    setBadge("firewall-status-pill", parsed.statusLabel, parsed.tone);
    renderDetailList("firewall-details", parsed.details, "No firewall details could be parsed.");
    state.firewallRules.columns = parsed.columns;
    state.firewallRules.rows = parsed.rows;
    state.firewallRules.emptyText = parsed.emptyText;
    state.firewallRules.page = 1;
    renderFirewallRulesTable();
}

function renderFirewallError(message) {
    renderFirewallInstallState(false);
    setText("firewall-summary-copy", summarizeOutput(message, false));
    setText("firewall-policy-summary", "Status refresh failed.");
    setBadge("firewall-status-pill", "Refresh failed", "danger");
    renderDetailList("firewall-details", [["Error", summarizeOutput(message, false)]], "Status refresh failed.");
    state.firewallRules.columns = ["Status"];
    state.firewallRules.rows = [];
    state.firewallRules.emptyText = "Unable to read the rules list.";
    state.firewallRules.page = 1;
    renderFirewallRulesTable();
}

function renderFirewallMissing() {
    const tool = getCurrentFirewallTool();
    renderFirewallInstallState(true);
    setText("firewall-backend-label", tool.label);
    setText("firewall-policy-summary", `${tool.label} is not installed.`);
    state.firewallRules.columns = ["Status"];
    state.firewallRules.rows = [];
    state.firewallRules.emptyText = `${tool.label} is not installed.`;
    state.firewallRules.page = 1;
}

function renderFail2BanStatus(parsed) {
    renderFail2BanInstallState(false);
    setText("fail2ban-service-state", parsed.serviceState);
    setText("fail2ban-service-copy", parsed.summary);
    setText("fail2ban-jail-count", String(parsed.jailCount));
    setBadge("fail2ban-service-pill", parsed.serviceState, parsed.tone);
    renderDetailList("fail2ban-details", parsed.details, "No Fail2Ban overview status could be parsed.");
    renderTokenRow("fail2ban-jail-list", parsed.jails, {
        clickable: true,
        emptyText: "No jails",
        onClick: jail => {
            fillJailInputs(jail);
            loadFail2BanJail(jail);
        },
    });
}

function renderFail2BanMissing() {
    renderFail2BanInstallState(true);
    setText("fail2ban-service-state", "Not installed");
    setText("fail2ban-service-copy", "Fail2Ban is not installed.");
    setText("fail2ban-jail-count", "--");
    clearFail2BanJail("Fail2Ban is not installed.");
}

function renderFail2BanJail(parsed, tone = "success") {
    state.currentJail = parsed.name;
    setText("fail2ban-current-jail", parsed.name);
    setText("fail2ban-current-jail-copy", parsed.summary);
    setBadge("fail2ban-jail-pill", parsed.name, tone);
    renderMetricCards("fail2ban-jail-metrics", parsed.metrics);
    renderDetailList("fail2ban-jail-details", parsed.details, "No jail details could be parsed.");
    renderTokenRow("fail2ban-banned-ips", parsed.bannedIps, {
        emptyText: "There are no banned IPs",
    });
    fillJailInputs(parsed.name);
}

function clearFail2BanJail(message) {
    state.currentJail = "";
    setText("fail2ban-current-jail", "Not selected");
    setText("fail2ban-current-jail-copy", message);
    setBadge("fail2ban-jail-pill", "Not selected");
    renderMetricCards("fail2ban-jail-metrics", []);
    renderDetailList("fail2ban-jail-details", [], message);
    renderTokenRow("fail2ban-banned-ips", [], {
        emptyText: "There are no banned IPs",
    });
}

function showCommandResult(prefix, label, text, ok = true, summaryOverride = "") {
    setBadge(`${prefix}-command-label`, label, ok ? "success" : "danger");
    setCallout(`${prefix}-result-summary`, summaryOverride || summarizeOutput(text, ok), ok ? "success" : "danger");
}

async function execute(prefix, label, argsOrScript, options = {}) {
    const commandLabel = Array.isArray(argsOrScript) ? argsOrScript.join(" ") : argsOrScript;
    const shouldUpdateResult = options.updateResult !== false;

    if (shouldUpdateResult)
        showCommandResult(prefix, label, `Running...\n\n${commandLabel}`, true, "Running command...");

    const result = await capture(argsOrScript, options);
    if (shouldUpdateResult) {
        showCommandResult(prefix, result.ok ? label : `${label} Failed`, result.output, result.ok, options.summary);
        refreshSecurityLogs();
    }

    return result;
}

async function refreshFirewallStatus() {
    return withRefreshLock("firewall", async () => {
        if (state.superuserAllowed !== true)
            return;

        const installed = await checkToolInstalled(state.firewallBackend, { force: true });
        if (!installed) {
            renderFirewallMissing();
            return;
        }

        renderFirewallInstallState(false);
        setText("firewall-summary-copy", "Refreshing firewall status...");
        setBadge("firewall-status-pill", "Loading", "loading");

        if (state.firewallBackend === "ufw") {
            const ufwCommand = getToolCommand("ufw");
            const [verboseResult, numberedResult] = await Promise.all([
                capture([ufwCommand, "status", "verbose"]),
                capture([ufwCommand, "status", "numbered"]),
            ]);

            if (!verboseResult.ok && !numberedResult.ok) {
                renderFirewallError(numberedResult.output || verboseResult.output);
                return;
            }

            renderFirewallStatus(parseUfwStatus(numberedResult.output, verboseResult.output));
            return;
        }

        const listResult = await capture([getToolCommand("iptables"), "-L", "INPUT", "-n", "--line-numbers", "-v"]);

        if (!listResult.ok) {
            renderFirewallError(listResult.output);
            return;
        }

        renderFirewallStatus(parseIptablesStatus(listResult.output));
    });
}

async function refreshFail2BanStatus() {
    return withRefreshLock("fail2ban", async () => {
        if (state.superuserAllowed !== true)
            return;

        const installed = await checkToolInstalled("fail2ban", { force: true });
        if (!installed) {
            renderFail2BanMissing();
            return;
        }

        renderFail2BanInstallState(false);
        setText("fail2ban-service-copy", "Refreshing Fail2Ban status...");
        setBadge("fail2ban-service-pill", "Loading", "loading");

        const serviceName = await resolveFail2BanService();
        const [serviceResult, statusResult] = await Promise.all([
            capture([
                "systemctl",
                "show",
                serviceName,
                "--property=Id,Description,LoadState,ActiveState,SubState,UnitFileState,FragmentPath",
            ]),
            capture([getToolCommand("fail2ban"), "status"]),
        ]);

        const parsed = parseFail2BanOverview(serviceResult.output, statusResult.output, serviceResult.ok, statusResult.ok);
        renderFail2BanStatus(parsed);

        if (state.currentJail) {
            if (parsed.jails.includes(state.currentJail))
                await loadFail2BanJail(state.currentJail, { quiet: true });
            else
                clearFail2BanJail("The current jail is no longer in the list. Select another jail.");
        }
    });
}

async function loadFail2BanJail(jail, options = {}) {
    if (state.superuserAllowed !== true)
        return;

    const jailName = jail.trim();
    if (!jailName) {
        showCommandResult("fail2ban", "Jail query failed", "Jail name cannot be empty.", false);
        return;
    }

    setBadge("fail2ban-jail-pill", "Loading", "loading");
    setText("fail2ban-current-jail", jailName);
    setText("fail2ban-current-jail-copy", "Loading jail details...");

    const result = await capture([getToolCommand("fail2ban"), "status", jailName]);
    if (!result.ok) {
        const summary = summarizeOutput(result.output, false);
        setText("fail2ban-current-jail", jailName);
        setText("fail2ban-current-jail-copy", summary);
        setBadge("fail2ban-jail-pill", "Load failed", "danger");
        renderMetricCards("fail2ban-jail-metrics", []);
        renderDetailList("fail2ban-jail-details", [["Error", summary]], "Jail query failed.");
        renderTokenRow("fail2ban-banned-ips", [], {
            emptyText: "There are no banned IPs",
        });
        if (!options.quiet)
            showCommandResult("fail2ban", `jail: ${jailName} Failed`, result.output, false, summary);
        return;
    }

    const parsed = parseFail2BanJail(result.output, jailName);
    renderFail2BanJail(parsed);
    if (!options.quiet)
        showCommandResult("fail2ban", `jail: ${jailName}`, result.output, true, parsed.summary);
}

function switchFirewallBackend(backend, options = {}) {
    state.firewallBackend = backend;

    document.querySelectorAll(".backend-button").forEach(button => {
        const active = button.dataset.backend === backend;
        button.classList.toggle("pf-m-selected", active);
        button.setAttribute("aria-pressed", active ? "true" : "false");
    });

    updateFirewallActionBar();
    // Only reveal/hide the settings vs install state once detection has actually run.
    // While still null (not yet checked) keep both hidden so we never flash the
    // operations UI for a tool that may turn out to be missing.
    if (state.toolInstalled[backend] !== null)
        renderFirewallInstallState(state.toolInstalled[backend] === false);
    setText("firewall-backend-label", getCurrentFirewallTool().label);
    if (state.firewallDialog.open)
        closeFirewallDialog();
    if (options.refresh !== false)
        refreshFirewallStatus();
}

function getFormValue(form, name) {
    const field = form.elements.namedItem(name);
    return typeof field?.value === "string" ? field.value.trim() : "";
}

function fillJailInputs(jail) {
    const jailInput = document.getElementById("fail2ban-jail-input");
    const unbanInput = document.getElementById("fail2ban-unban-jail-input");
    if (jailInput)
        jailInput.value = jail;
    if (unbanInput)
        unbanInput.value = jail;
}

function updateFirewallActionBar() {
    const isUfw = state.firewallBackend === "ufw";
    const addButton = getElement("firewall-add-button");

    setHidden("firewall-enable-button", !isUfw);
    setHidden("firewall-disable-button", !isUfw);
    setHidden("firewall-reload-button", !isUfw);

    if (addButton)
        addButton.textContent = isUfw ? "Add rule" : "Insert rule";
}

function resetFirewallDialog() {
    state.firewallDialog = {
        open: false,
        mode: "",
        busy: false,
        error: "",
    };
}

function updateFirewallDialog(patch) {
    state.firewallDialog = {
        ...state.firewallDialog,
        ...patch,
    };
    renderFirewallDialog();
}

function setFirewallRuleActionOptions() {
    const select = getElement("firewall-rule-action");
    if (!select)
        return;

    const options = state.firewallBackend === "ufw"
        ? [
            { value: "allow", label: "allow" },
            { value: "deny", label: "deny" },
            { value: "reject", label: "reject" },
        ]
        : [
            { value: "ACCEPT", label: "ACCEPT" },
            { value: "DROP", label: "DROP" },
            { value: "REJECT", label: "REJECT" },
        ];

    select.replaceChildren();
    options.forEach(option => {
        const element = document.createElement("option");
        element.value = option.value;
        element.textContent = option.label;
        select.append(element);
    });
}

function renderFirewallDialog() {
    const dialog = getElement("firewall-modal");
    const title = getElement("firewall-modal-title");
    const copy = getElement("firewall-modal-copy");
    const form = getElement("firewall-rule-form");
    const alert = getElement("firewall-modal-alert");
    const submit = getElement("firewall-modal-submit");
    const cancel = getElement("firewall-modal-cancel");
    const close = getElement("firewall-modal-close");

    if (!dialog || !title || !copy || !form || !alert || !submit || !cancel || !close)
        return;

    const current = state.firewallDialog;
    dialog.hidden = !current.open;
    if (!current.open)
        return;

    const isEnable = current.mode === "enable-ufw";
    title.textContent = isEnable
        ? "Enable UFW"
        : state.firewallBackend === "ufw"
            ? "Add UFW rule"
            : "Insert iptables rule";
    copy.hidden = !isEnable;
    copy.textContent = isEnable
        ? "This will enable UFW immediately and apply the current rules. Make sure the port needed for your current management connection is allowed first."
        : "";
    form.hidden = isEnable;
    alert.hidden = !current.error;
    alert.textContent = current.error;
    submit.textContent = isEnable
        ? (current.busy ? "Enabling..." : "Enable")
        : current.busy
            ? (state.firewallBackend === "ufw" ? "Adding..." : "Inserting...")
            : state.firewallBackend === "ufw"
                ? "Add"
                : "Insert";
    submit.disabled = current.busy;
    cancel.disabled = current.busy;
    close.disabled = current.busy;
    form.querySelectorAll("input, select").forEach(field => {
        field.disabled = current.busy;
    });
}

function openFirewallEnableDialog() {
    updateFirewallDialog({
        open: true,
        mode: "enable-ufw",
        busy: false,
        error: "",
    });
}

function openFirewallRuleDialog() {
    const form = getElement("firewall-rule-form");
    if (form)
        form.reset();

    setFirewallRuleActionOptions();
    const portInput = getElement("firewall-rule-port");
    if (portInput)
        portInput.removeAttribute("aria-invalid");
    updateFirewallDialog({
        open: true,
        mode: "add-rule",
        busy: false,
        error: "",
    });
}

function closeFirewallDialog() {
    resetFirewallDialog();
    renderFirewallDialog();
}

function confirmDestructiveAction(message) {
    return new Promise(resolve => {
        const confirmed = window.confirm(message);
        resolve(confirmed);
    });
}

async function deleteFirewallRule(rule) {
    if (!rule)
        return;

    const label = rule.kind === "ufw" ? "UFW rule" : "iptables rule";
    const confirmed = await confirmDestructiveAction(`Delete ${label} #${rule.value}? This action cannot be undone.`);
    if (!confirmed)
        return;

    const result = rule.kind === "ufw"
        ? await execute("firewall", "Delete UFW rule", [getToolCommand("ufw"), "--force", "delete", rule.value])
        : await execute("firewall", "Delete iptables rule", [getToolCommand("iptables"), "-D", "INPUT", rule.value]);

    if (result.ok)
        await refreshFirewallStatus();
}

async function handleFirewallDialogSubmit() {
    if (!state.firewallDialog.open || state.firewallDialog.busy)
        return;

    if (state.firewallDialog.mode === "enable-ufw") {
        updateFirewallDialog({ busy: true, error: "" });
        const result = await execute("firewall", "Enable UFW", [getToolCommand("ufw"), "--force", "enable"]);
        if (!result.ok) {
            updateFirewallDialog({
                busy: false,
                error: summarizeOutput(result.output, false),
            });
            return;
        }

        closeFirewallDialog();
        await refreshFirewallStatus();
        return;
    }

    const form = getElement("firewall-rule-form");
    if (!form)
        return;

    const action = getFormValue(form, "action");
    const port = getFormValue(form, "port");
    const protocol = getFormValue(form, "protocol");
    const source = getFormValue(form, "source");

    if (!port) {
        updateFirewallDialog({ error: "Port cannot be empty." });
        const portInput = getElement("firewall-rule-port");
        if (portInput)
            portInput.setAttribute("aria-invalid", "true");
        return;
    }
    const portInput = getElement("firewall-rule-port");
    if (portInput)
        portInput.removeAttribute("aria-invalid");

    const args = state.firewallBackend === "ufw"
        ? source
            ? [getToolCommand("ufw"), action, "from", source, "to", "any", "port", port, "proto", protocol]
            : [getToolCommand("ufw"), action, `${port}/${protocol}`]
        : (() => {
            const command = [getToolCommand("iptables"), "-I", "INPUT", "-p", protocol];
            if (source)
                command.push("-s", source);
            command.push("--dport", port, "-j", action);
            return command;
        })();

    const label = state.firewallBackend === "ufw" ? "Add UFW rule" : "Insert iptables rule";
    updateFirewallDialog({ busy: true, error: "" });
    const result = await execute("firewall", label, args);
    if (!result.ok) {
        updateFirewallDialog({
            busy: false,
            error: summarizeOutput(result.output, false),
        });
        return;
    }

    closeFirewallDialog();
    form.reset();
    await refreshFirewallStatus();
}

async function handleQuickAction(action) {
    const fail2banService = state.fail2banService || "fail2ban.service";
    const actions = {
        "ufw-disable": () => execute("firewall", "Disable UFW", [getToolCommand("ufw"), "disable"]),
        "ufw-reload": () => execute("firewall", "Reload UFW", [getToolCommand("ufw"), "reload"]),
        "fail2ban-start": () => execute("fail2ban", "Start Fail2Ban", ["systemctl", "start", fail2banService]),
        "fail2ban-stop": () => execute("fail2ban", "Stop Fail2Ban", ["systemctl", "stop", fail2banService]),
        "fail2ban-restart": () => execute("fail2ban", "Restart Fail2Ban", ["systemctl", "restart", fail2banService]),
        "fail2ban-reload": () => execute("fail2ban", "Reload Fail2Ban", [getToolCommand("fail2ban"), "reload"]),
    };

    const handler = actions[action];
    if (!handler)
        return;

    await handler();

    if (action.startsWith("ufw") || action.startsWith("iptables"))
        await refreshFirewallStatus();

    if (action.startsWith("fail2ban"))
        await refreshFail2BanStatus();
}

async function handleFail2BanJail(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const jail = getFormValue(form, "jail");
    await loadFail2BanJail(jail);
}

async function handleFail2BanUnban(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const jail = getFormValue(form, "jail");
    const ip = getFormValue(form, "ip");

    if (!jail || !ip) {
        showCommandResult("fail2ban", "Unban failed", "Jail and IP cannot be empty.", false);
        return;
    }

    fillJailInputs(jail);
    await execute("fail2ban", "Unban Fail2Ban IP", [getToolCommand("fail2ban"), "set", jail, "unbanip", ip]);
    form.reset();
    fillJailInputs(jail);
    await refreshFail2BanStatus();
    await loadFail2BanJail(jail, { quiet: true });
}

function bindEvents() {
    document.querySelectorAll(".backend-button").forEach(button => {
        button.addEventListener("click", () => switchFirewallBackend(button.dataset.backend));
    });

    document.querySelectorAll("[data-action]").forEach(button => {
        button.addEventListener("click", () => handleQuickAction(button.dataset.action));
    });

    document.querySelectorAll("[data-install-tool]").forEach(button => {
        button.addEventListener("click", () => openInstallDialog(button.dataset.installTool));
    });

    document.getElementById("security-access-action")?.addEventListener("click", requestSuperuserAccess);
    document.getElementById("security-auth-form")?.addEventListener("submit", handleSuperuserDialogSubmit);
    document.getElementById("security-auth-form")?.addEventListener("input", handleSuperuserDialogInput);
    document.getElementById("security-auth-form")?.addEventListener("change", handleSuperuserDialogInput);
    document.getElementById("security-auth-cancel")?.addEventListener("click", () => closeSuperuserDialog());
    document.getElementById("security-auth-close")?.addEventListener("click", () => closeSuperuserDialog());
    document.getElementById("firewall-enable-button")?.addEventListener("click", openFirewallEnableDialog);
    document.getElementById("firewall-add-button")?.addEventListener("click", openFirewallRuleDialog);
    document.getElementById("firewall-modal-submit")?.addEventListener("click", handleFirewallDialogSubmit);
    document.getElementById("firewall-modal-cancel")?.addEventListener("click", closeFirewallDialog);
    document.getElementById("firewall-modal-close")?.addEventListener("click", closeFirewallDialog);
    document.getElementById("firewall-rule-form")?.addEventListener("submit", event => {
        event.preventDefault();
        handleFirewallDialogSubmit();
    });
    document.getElementById("firewall-modal")?.addEventListener("click", event => {
        if (event.target?.id === "firewall-modal")
            closeFirewallDialog();
    });
    document.getElementById("security-install-submit")?.addEventListener("click", handleInstallDialogSubmit);
    document.getElementById("security-install-cancel")?.addEventListener("click", closeInstallDialog);
    document.getElementById("security-install-close")?.addEventListener("click", closeInstallDialog);
    document.getElementById("security-install-dialog")?.addEventListener("click", event => {
        if (event.target?.id === "security-install-dialog")
            closeInstallDialog();
    });
    document.getElementById("security-auth-dialog")?.addEventListener("click", event => {
        if (event.target?.id === "security-auth-dialog")
            closeSuperuserDialog();
    });
    document.getElementById("firewall-rules-prev")?.addEventListener("click", () => {
        state.firewallRules.page = Math.max(1, state.firewallRules.page - 1);
        renderFirewallRulesTable();
    });
    document.getElementById("firewall-rules-next")?.addEventListener("click", () => {
        const totalPages = getFirewallRuleTotalPages();
        state.firewallRules.page = Math.min(totalPages, state.firewallRules.page + 1);
        renderFirewallRulesTable();
    });
    document.getElementById("firewall-rules-page-go")?.addEventListener("click", () => {
        jumpToFirewallRulesPage(document.getElementById("firewall-rules-page-jump")?.value);
    });
    document.getElementById("firewall-rules-page-jump")?.addEventListener("change", event => {
        jumpToFirewallRulesPage(event.target.value);
    });
    document.getElementById("firewall-rules-page-jump")?.addEventListener("keydown", event => {
        if (event.key !== "Enter")
            return;

        event.preventDefault();
        jumpToFirewallRulesPage(event.target.value);
    });
    document.getElementById("security-log-source-toggle")?.addEventListener("click", () => {
        positionSecurityLogMenu();
        toggleSecurityLogMenu();
    });
    document.addEventListener("click", event => {
        const menu = document.getElementById("security-log-menu");
        const toggle = document.getElementById("security-log-source-toggle");
        if (menu && !menu.hidden && toggle && !toggle.contains(event.target) && !menu.contains(event.target))
            closeSecurityLogMenu();
    });
    document.getElementById("security-log-refresh")?.addEventListener("click", refreshSecurityLogs);
    document.getElementById("security-log-view-all")?.addEventListener("click", () => {
        cockpit.jump(getSecurityLogUrl());
    });
    document.getElementById("fail2ban-jail-form")?.addEventListener("submit", handleFail2BanJail);
    document.getElementById("fail2ban-unban-form")?.addEventListener("submit", handleFail2BanUnban);

    document.addEventListener("visibilitychange", () => {
        if (document.hidden) {
            stopAutoRefresh();
            return;
        }

        if (state.superuserAllowed === true) {
            refreshSecurityPage();
            startAutoRefresh();
        }
    });

    document.addEventListener("keydown", event => {
        if (event.key === "Escape" && state.firewallDialog.open) {
            closeFirewallDialog();
            return;
        }

        if (event.key === "Escape" && state.installDialog.open) {
            closeInstallDialog();
            return;
        }

        if (event.key === "Escape" && state.superuserDialog.open)
            closeSuperuserDialog();
    });
}

document.addEventListener("DOMContentLoaded", async () => {
    bindEvents();
    bindDarkMode();
    initSuperuser();
    renderSecurityLogSourceOptions();
    clearFail2BanJail("Open a jail from the list or enter a name manually.");
    switchFirewallBackend(state.firewallBackend, { refresh: false });
    renderFirewallDialog();
    renderInstallDialog();
    renderSuperuserDialog();
    renderAccessState();
});
