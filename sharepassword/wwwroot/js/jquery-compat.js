(function () {
    if (window.jQuery && typeof window.jQuery.parseJSON !== "function") {
        window.jQuery.parseJSON = JSON.parse;
    }
})();
