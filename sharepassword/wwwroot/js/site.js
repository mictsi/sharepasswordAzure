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

	const passwordRequirementKeys = ["length", "lowercase", "uppercase", "number", "symbol"];
	const passwordPolicyMessage = "Use at least 12 characters with lowercase, uppercase, a number, and a symbol.";
	const generatedPasswordLength = 20;
	const passwordCharacterSets = {
		lowercase: "abcdefghijkmnopqrstuvwxyz",
		uppercase: "ABCDEFGHJKLMNPQRSTUVWXYZ",
		number: "23456789",
		symbol: "!@#$%^&*()-_=+[]{};:,.?"
	};

	function getRandomIndex(length) {
		if (window.crypto && window.crypto.getRandomValues) {
			const values = new Uint32Array(1);
			window.crypto.getRandomValues(values);
			return values[0] % length;
		}

		return Math.floor(Math.random() * length);
	}

	function pickCharacter(characters) {
		return characters.charAt(getRandomIndex(characters.length));
	}

	function shuffleCharacters(characters) {
		for (let index = characters.length - 1; index > 0; index--) {
			const swapIndex = getRandomIndex(index + 1);
			const current = characters[index];
			characters[index] = characters[swapIndex];
			characters[swapIndex] = current;
		}

		return characters;
	}

	function generatePassword() {
		const characters = [
			pickCharacter(passwordCharacterSets.lowercase),
			pickCharacter(passwordCharacterSets.uppercase),
			pickCharacter(passwordCharacterSets.number),
			pickCharacter(passwordCharacterSets.symbol)
		];
		const allCharacters = passwordCharacterSets.lowercase + passwordCharacterSets.uppercase + passwordCharacterSets.number + passwordCharacterSets.symbol;

		while (characters.length < generatedPasswordLength) {
			characters.push(pickCharacter(allCharacters));
		}

		return shuffleCharacters(characters).join("");
	}

	function analyzePassword(password) {
		const value = password || "";
		const requirements = {
			length: value.length >= 12,
			lowercase: /[a-z]/.test(value),
			uppercase: /[A-Z]/.test(value),
			number: /\d/.test(value),
			symbol: /[^A-Za-z0-9]/.test(value)
		};
		const metCount = passwordRequirementKeys.filter(function (key) {
			return requirements[key];
		}).length;

		let label = "Enter a password";
		if (value) {
			label = metCount <= 2 ? "Weak" : metCount < passwordRequirementKeys.length ? "Fair" : "Strong";
		}

		return {
			requirements,
			metCount,
			label,
			isValid: metCount === passwordRequirementKeys.length
		};
	}

	function updatePasswordMeters(input, analysis) {
		document.querySelectorAll("[data-password-strength]").forEach(function (meter) {
			if (meter.getAttribute("data-password-strength") !== input.id) {
				return;
			}

			meter.setAttribute("data-strength-level", analysis.metCount.toString());

			const bar = meter.querySelector("[data-password-strength-bar]");
			if (bar) {
				bar.style.width = (analysis.metCount / passwordRequirementKeys.length * 100) + "%";
			}

			const label = meter.querySelector("[data-password-strength-label]");
			if (label) {
				label.textContent = analysis.label;
			}

			const count = meter.querySelector("[data-password-strength-count]");
			if (count) {
				count.textContent = analysis.metCount + "/" + passwordRequirementKeys.length + " requirements";
			}

			passwordRequirementKeys.forEach(function (key) {
				const requirement = meter.querySelector("[data-password-requirement=\"" + key + "\"]");
				if (requirement) {
					requirement.classList.toggle("is-met", analysis.requirements[key]);
				}
			});
		});
	}

	function updatePasswordConfirmation(confirmInput) {
		const targetId = confirmInput.getAttribute("data-password-confirm-for");
		const target = targetId ? document.getElementById(targetId) : null;
		if (!target || !("value" in target)) {
			return;
		}

		confirmInput.setCustomValidity(!confirmInput.value || confirmInput.value === target.value
			? ""
			: "The password confirmation does not match.");
	}

	function updatePasswordInput(input) {
		const analysis = analyzePassword(input.value);
		input.setCustomValidity(!input.value || analysis.isValid ? "" : passwordPolicyMessage);
		updatePasswordMeters(input, analysis);

		if (input.id) {
			document.querySelectorAll("[data-password-confirm-for=\"" + input.id + "\"]").forEach(updatePasswordConfirmation);
		}
	}

	function dispatchInputEvents(input) {
		input.dispatchEvent(new Event("input", { bubbles: true }));
		input.dispatchEvent(new Event("change", { bubbles: true }));
	}

	function setGeneratedPassword(trigger) {
		const targetId = trigger.getAttribute("data-password-target");
		const confirmTargetId = trigger.getAttribute("data-password-confirm-target");
		const target = targetId ? document.getElementById(targetId) : null;
		const confirmTarget = confirmTargetId ? document.getElementById(confirmTargetId) : null;
		if (!target || !("value" in target)) {
			return;
		}

		const password = generatePassword();
		target.value = password;
		if ("type" in target && target.type === "password") {
			target.type = "text";
		}

		dispatchInputEvents(target);

		if (confirmTarget && "value" in confirmTarget) {
			confirmTarget.value = password;
			if ("type" in confirmTarget && confirmTarget.type === "password") {
				confirmTarget.type = "text";
			}

			dispatchInputEvents(confirmTarget);
		}

		target.focus();
		if (typeof target.select === "function") {
			target.select();
		}
		flashButtonLabel(trigger, "Generated");
	}

	function validatePasswordFields(form) {
		let isValid = true;

		form.querySelectorAll("[data-password-policy]").forEach(function (input) {
			updatePasswordInput(input);
			isValid = input.validity.valid && isValid;
		});

		form.querySelectorAll("[data-password-confirm-for]").forEach(function (input) {
			updatePasswordConfirmation(input);
			isValid = input.validity.valid && isValid;
		});

		return isValid;
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
		const generateTrigger = event.target.closest("[data-generate-password]");
		if (generateTrigger) {
			event.preventDefault();
			setGeneratedPassword(generateTrigger);
			return;
		}

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

	document.addEventListener("input", function (event) {
		if (!(event.target instanceof Element)) {
			return;
		}

		const passwordInput = event.target.closest("[data-password-policy]");
		if (passwordInput) {
			updatePasswordInput(passwordInput);
			return;
		}

		const confirmInput = event.target.closest("[data-password-confirm-for]");
		if (confirmInput) {
			updatePasswordConfirmation(confirmInput);
		}
	});

	document.addEventListener("submit", function (event) {
		const form = event.target.closest("form");
		if (!form) {
			return;
		}

		if (!validatePasswordFields(form)) {
			event.preventDefault();
			if (form.reportValidity) {
				form.reportValidity();
			}

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

	document.querySelectorAll("[data-password-policy]").forEach(updatePasswordInput);
	document.querySelectorAll("[data-password-confirm-for]").forEach(updatePasswordConfirmation);
})();
