(function () {
    const maxChars = 1000;
    const payloadVersion = 1;
    const kdfIterations = 310000;
    const minimumExtraPasswordLength = 12;
    const algorithmName = "AES-256-GCM";
    const kdfName = "PBKDF2-SHA256";

    function hasWebCrypto() {
        return Boolean(
            window.crypto &&
            window.crypto.subtle &&
            window.crypto.getRandomValues &&
            window.TextEncoder &&
            window.TextDecoder);
    }

    function bytesToBase64(bytes) {
        let binary = "";
        const chunkSize = 0x8000;

        for (let index = 0; index < bytes.length; index += chunkSize) {
            const chunk = bytes.subarray(index, index + chunkSize);
            binary += String.fromCharCode.apply(null, chunk);
        }

        return window.btoa(binary);
    }

    function base64ToBytes(value) {
        const binary = window.atob(value);
        const bytes = new Uint8Array(binary.length);

        for (let index = 0; index < binary.length; index += 1) {
            bytes[index] = binary.charCodeAt(index);
        }

        return bytes;
    }

    function encodeText(value) {
        return new TextEncoder().encode(value);
    }

    function decodeText(value) {
        return new TextDecoder().decode(value);
    }

    async function deriveAesKey(extraPassword, salt, usages) {
        const baseKey = await window.crypto.subtle.importKey(
            "raw",
            encodeText(extraPassword),
            "PBKDF2",
            false,
            ["deriveKey"]);

        return window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: kdfIterations,
                hash: "SHA-256"
            },
            baseKey,
            {
                name: "AES-GCM",
                length: 256
            },
            false,
            usages);
    }

    async function encryptSecret(secret, extraPassword) {
        const salt = new Uint8Array(16);
        const nonce = new Uint8Array(12);
        window.crypto.getRandomValues(salt);
        window.crypto.getRandomValues(nonce);

        const key = await deriveAesKey(extraPassword, salt, ["encrypt"]);
        const ciphertext = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: nonce
            },
            key,
            encodeText(secret));

        return JSON.stringify({
            version: payloadVersion,
            algorithm: algorithmName,
            kdf: kdfName,
            iterations: kdfIterations,
            salt: bytesToBase64(salt),
            nonce: bytesToBase64(nonce),
            ciphertext: bytesToBase64(new Uint8Array(ciphertext))
        });
    }

    async function decryptSecret(payloadJson, extraPassword) {
        const payload = JSON.parse(payloadJson);
        if (
            payload.version !== payloadVersion ||
            payload.algorithm !== algorithmName ||
            payload.kdf !== kdfName ||
            payload.iterations !== kdfIterations) {
            throw new Error("Unsupported encrypted payload.");
        }

        const salt = base64ToBytes(payload.salt);
        const nonce = base64ToBytes(payload.nonce);
        const ciphertext = base64ToBytes(payload.ciphertext);
        const key = await deriveAesKey(extraPassword, salt, ["decrypt"]);
        const plaintext = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: nonce
            },
            key,
            ciphertext);

        return decodeText(plaintext);
    }

    function setStatus(status, text, state) {
        if (!status) {
            return;
        }

        const textTarget = status.querySelector("[data-encryption-status-text], [data-decryption-status-text]");
        const spinner = status.querySelector(".encryption-status__spinner");

        if (textTarget) {
            textTarget.textContent = text;
        }

        if (spinner) {
            spinner.hidden = state !== "working";
        }

        status.classList.remove("d-none", "is-error", "is-success", "is-working");
        status.classList.add(`is-${state}`);
    }

    function clearStatus(status) {
        if (status) {
            status.classList.add("d-none");
            status.classList.remove("is-error", "is-success", "is-working");
        }
    }

    function nextFrame() {
        return new Promise((resolve) => window.requestAnimationFrame(resolve));
    }

    function wireCounter(inputId, counterId, warningId) {
        const input = document.getElementById(inputId);
        const counter = document.getElementById(counterId);
        const warning = document.getElementById(warningId);

        if (!input || !counter || !warning) {
            return;
        }

        function updateCount() {
            const length = input.value.length;
            const remaining = Math.max(0, maxChars - length);
            counter.textContent = `${length} / ${maxChars} characters (${remaining} left)`;

            if (length > maxChars) {
                warning.classList.remove("d-none");
                counter.classList.add("text-danger");
            } else {
                warning.classList.add("d-none");
                counter.classList.remove("text-danger");
            }
        }

        input.addEventListener("input", updateCount);
        updateCount();
    }

    function isFormValid(form) {
        if (window.jQuery && window.jQuery.fn && typeof window.jQuery.fn.valid === "function") {
            return window.jQuery(form).valid();
        }

        return form.checkValidity();
    }

    function setupCreateForm() {
        const form = document.querySelector("form[data-client-encryption-create]");
        if (!form) {
            return;
        }

        const expiryHours = document.getElementById("ExpiryHours");
        const presetInputs = Array.from(document.querySelectorAll('input[name="expiryPreset"]'));
        const secretInput = document.getElementById("secretText");
        const clearButton = document.getElementById("clearSecretButton");
        const useClientEncryption = document.getElementById("UseClientEncryption");
        const encryptedPayload = document.getElementById("ClientEncryptedPasswordPayload");
        const panel = document.getElementById("clientEncryptionPanel");
        const extraPassword = document.getElementById("extraPassword");
        const confirmExtraPassword = document.getElementById("confirmExtraPassword");
        const status = document.getElementById("clientEncryptionStatus");
        const submitButtons = Array.from(form.querySelectorAll('button[type="submit"], input[type="submit"]'));

        function syncExpiryValue() {
            const selected = presetInputs.find((input) => input.checked);
            if (!selected || !expiryHours) {
                return;
            }

            expiryHours.value = selected.value;
        }

        function setClientEncryptionUi() {
            const enabled = Boolean(useClientEncryption && useClientEncryption.checked);
            if (panel) {
                panel.classList.toggle("d-none", !enabled);
            }

            if (extraPassword) {
                extraPassword.required = enabled;
            }

            if (confirmExtraPassword) {
                confirmExtraPassword.required = enabled;
            }

            if (!enabled) {
                if (encryptedPayload) {
                    encryptedPayload.value = "";
                }

                if (extraPassword) {
                    extraPassword.value = "";
                }

                if (confirmExtraPassword) {
                    confirmExtraPassword.value = "";
                }

                clearStatus(status);
            }
        }

        wireCounter("secretText", "secretTextCounter", "secretTextWarning");
        wireCounter("instructionsText", "instructionsTextCounter", "instructionsTextWarning");
        presetInputs.forEach((input) => input.addEventListener("change", syncExpiryValue));
        syncExpiryValue();

        clearButton?.addEventListener("click", function () {
            if (!secretInput) {
                return;
            }

            secretInput.value = "";
            secretInput.dispatchEvent(new Event("input", { bubbles: true }));
            secretInput.focus();
        });

        useClientEncryption?.addEventListener("change", setClientEncryptionUi);
        setClientEncryptionUi();

        form.addEventListener("submit", async function (event) {
            if (!useClientEncryption || !useClientEncryption.checked) {
                if (encryptedPayload) {
                    encryptedPayload.value = "";
                }

                return;
            }

            event.preventDefault();

            if (!isFormValid(form)) {
                return;
            }

            if (!secretInput || !encryptedPayload || !extraPassword || !confirmExtraPassword) {
                setStatus(status, "Browser encryption controls are unavailable.", "error");
                return;
            }

            if (!hasWebCrypto()) {
                setStatus(status, "This browser cannot encrypt the secret locally.", "error");
                return;
            }

            if (!secretInput.value) {
                setStatus(status, "Enter a secret before creating the share.", "error");
                secretInput.focus();
                return;
            }

            if (extraPassword.value.length < minimumExtraPasswordLength) {
                setStatus(status, `Extra password must be at least ${minimumExtraPasswordLength} characters.`, "error");
                extraPassword.focus();
                return;
            }

            if (extraPassword.value !== confirmExtraPassword.value) {
                setStatus(status, "Extra password confirmation does not match.", "error");
                confirmExtraPassword.focus();
                return;
            }

            submitButtons.forEach((button) => {
                button.disabled = true;
            });
            setStatus(status, "Encrypting secret...", "working");
            await nextFrame();

            try {
                encryptedPayload.value = await encryptSecret(secretInput.value, extraPassword.value);
                secretInput.value = "";
                secretInput.disabled = true;
                extraPassword.value = "";
                confirmExtraPassword.value = "";
                extraPassword.disabled = true;
                confirmExtraPassword.disabled = true;
                HTMLFormElement.prototype.submit.call(form);
            } catch {
                encryptedPayload.value = "";
                secretInput.disabled = false;
                extraPassword.disabled = false;
                confirmExtraPassword.disabled = false;
                submitButtons.forEach((button) => {
                    button.disabled = false;
                });
                setStatus(status, "Browser encryption failed. Try again.", "error");
            }
        });
    }

    function setupCredentialDecryption() {
        const panel = document.querySelector("[data-client-decryption]");
        if (!panel) {
            return;
        }

        const payloadSource = document.getElementById("credentialSecretEncryptedPayload");
        const rawSecret = document.getElementById("credentialSecretRaw");
        const extraPassword = document.getElementById("clientDecryptionPassword");
        const button = document.getElementById("clientDecryptButton");
        const status = document.getElementById("clientDecryptionStatus");
        const secretContainer = document.getElementById("credentialSecret");
        const secretOutput = secretContainer?.querySelector("[data-secret-output]");
        const secretButtons = Array.from(document.querySelectorAll('[data-secret-toggle="credentialSecret"], [data-copy-target="credentialSecretRaw"]'));

        async function decryptFromInput() {
            if (!payloadSource || !rawSecret || !extraPassword || !button || !secretContainer || !secretOutput) {
                setStatus(status, "Browser decryption controls are unavailable.", "error");
                return;
            }

            if (!hasWebCrypto()) {
                setStatus(status, "This browser cannot decrypt the secret locally.", "error");
                return;
            }

            if (!extraPassword.value) {
                setStatus(status, "Enter the extra password.", "error");
                extraPassword.focus();
                return;
            }

            button.disabled = true;
            setStatus(status, "Decrypting secret...", "working");
            await nextFrame();

            try {
                const plaintext = await decryptSecret(payloadSource.value, extraPassword.value);
                const mask = "*".repeat(Math.max(12, Math.min(plaintext.length, 32)));
                rawSecret.value = plaintext;
                extraPassword.value = "";
                secretContainer.setAttribute("data-secret-placeholder", mask);
                secretContainer.classList.remove("is-revealed");
                secretOutput.textContent = mask;
                secretOutput.classList.add("is-placeholder");
                secretButtons.forEach((secretButton) => {
                    secretButton.disabled = false;
                });
                setStatus(status, "Secret decrypted in this browser.", "success");
            } catch {
                rawSecret.value = "";
                secretButtons.forEach((secretButton) => {
                    secretButton.disabled = true;
                });
                setStatus(status, "Unable to decrypt. Check the extra password.", "error");
            } finally {
                button.disabled = false;
            }
        }

        button?.addEventListener("click", function (event) {
            event.preventDefault();
            decryptFromInput();
        });

        extraPassword?.addEventListener("keydown", function (event) {
            if (event.key === "Enter") {
                event.preventDefault();
                decryptFromInput();
            }
        });
    }

    setupCreateForm();
    setupCredentialDecryption();
})();
