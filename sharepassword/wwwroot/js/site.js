(function () {
	function getCopyValue(trigger) {
		const targetId = trigger.getAttribute("data-copy-target");
		if (targetId) {
			const target = document.getElementById(targetId);
			if (!target) {
				return "";
			}

			if ("value" in target) {
				return target.value;
			}

			return target.textContent || "";
		}

		return trigger.getAttribute("data-copy-value") || "";
	}

	async function copyText(value) {
		if (navigator.clipboard && window.isSecureContext) {
			await navigator.clipboard.writeText(value);
			return;
		}

		const fallback = document.createElement("textarea");
		fallback.value = value;
		fallback.setAttribute("readonly", "readonly");
		fallback.style.position = "fixed";
		fallback.style.opacity = "0";
		document.body.appendChild(fallback);
		fallback.focus();
		fallback.select();
		document.execCommand("copy");
		document.body.removeChild(fallback);
	}

	function flashButtonLabel(button, label) {
		if (!button.dataset.originalLabel) {
			button.dataset.originalLabel = button.textContent.trim();
		}

		button.textContent = label;

		if (button._copyTimer) {
			window.clearTimeout(button._copyTimer);
		}

		button._copyTimer = window.setTimeout(function () {
			button.textContent = button.dataset.originalLabel;
		}, 1600);
	}

	function setSecretState(container, isRevealed) {
		const sourceId = container.getAttribute("data-secret-source");
		const output = container.querySelector("[data-secret-output]");
		const source = sourceId ? document.getElementById(sourceId) : null;
		const placeholder = container.getAttribute("data-secret-placeholder") || "Hidden";
		const value = source && "value" in source ? source.value : source ? (source.textContent || "") : "";

		if (!output) {
			return;
		}

		container.classList.toggle("is-revealed", isRevealed);
		output.textContent = isRevealed ? value : placeholder;
		output.classList.toggle("is-placeholder", !isRevealed);
	}

	document.addEventListener("click", async function (event) {
		const copyTrigger = event.target.closest("[data-copy-target], [data-copy-value]");
		if (copyTrigger) {
			event.preventDefault();
			const value = getCopyValue(copyTrigger);
			if (!value) {
				return;
			}

			try {
				await copyText(value);
				flashButtonLabel(copyTrigger, copyTrigger.getAttribute("data-copy-success") || "Copied");
			} catch {
				flashButtonLabel(copyTrigger, "Copy failed");
			}

			return;
		}

		const passwordToggle = event.target.closest("[data-password-toggle]");
		if (passwordToggle) {
			event.preventDefault();
			const inputId = passwordToggle.getAttribute("data-password-toggle");
			const input = inputId ? document.getElementById(inputId) : null;
			if (!input || !("type" in input)) {
				return;
			}

			const shouldShow = input.type === "password";
			input.type = shouldShow ? "text" : "password";
			passwordToggle.classList.toggle("is-visible", shouldShow);
			passwordToggle.setAttribute("aria-label", shouldShow ? "Hide password" : "Show password");
			passwordToggle.setAttribute("aria-pressed", shouldShow ? "true" : "false");
			return;
		}

		const secretToggle = event.target.closest("[data-secret-toggle]");
		if (secretToggle) {
			event.preventDefault();
			const containerId = secretToggle.getAttribute("data-secret-toggle");
			const container = containerId ? document.getElementById(containerId) : null;
			if (!container) {
				return;
			}

			const shouldReveal = !container.classList.contains("is-revealed");
			setSecretState(container, shouldReveal);
			secretToggle.textContent = shouldReveal
				? (secretToggle.getAttribute("data-hide-label") || "Hide")
				: (secretToggle.getAttribute("data-show-label") || "Show");
		}
	});

	document.addEventListener("submit", function (event) {
		const form = event.target.closest("form[data-confirm]");
		if (!form) {
			return;
		}

		const message = form.getAttribute("data-confirm");
		if (message && !window.confirm(message)) {
			event.preventDefault();
		}
	});

	document.querySelectorAll("[data-secret-source]").forEach(function (container) {
		setSecretState(container, container.classList.contains("is-revealed"));
	});
})();
