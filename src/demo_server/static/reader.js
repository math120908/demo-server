(function () {
  "use strict";

  var tools = [];
  var openId = null;
  var justOpened = false;
  var initialized = false;
  var readyCbs = [];
  var uiState = null;

  function byId(id) {
    return document.getElementById(id);
  }

  function findTool(id) {
    var i;
    for (i = 0; i < tools.length; i += 1) {
      if (tools[i].id === id) return tools[i];
    }
    return null;
  }

  function findToolButton(id) {
    var rail = byId("mdr-rail");
    var buttons;
    var i;
    if (!rail) return null;
    buttons = rail.getElementsByTagName("button");
    for (i = 0; i < buttons.length; i += 1) {
      if (buttons[i].getAttribute("data-tool") === id) return buttons[i];
    }
    return null;
  }

  function applyUi(ui) {
    var root = document.documentElement;
    root.setAttribute("data-theme", ui.theme);
    if (ui.skin && ui.skin !== "default") {
      root.setAttribute("data-skin", ui.skin);
    } else {
      root.removeAttribute("data-skin");
    }
  }

  function getUi() {
    var stored = {};
    var legacy = null;
    var theme;
    var skin;

    if (uiState) {
      return { theme: uiState.theme, skin: uiState.skin };
    }

    try {
      stored = JSON.parse(localStorage.getItem("mdr-ui") || "{}");
      if (!stored || typeof stored !== "object") stored = {};
    } catch (e) {
      stored = {};
    }

    theme = stored.theme;
    if (theme !== "light" && theme !== "dark") {
      try {
        legacy = localStorage.getItem("theme");
      } catch (ignoreLegacyRead) {}
      theme = legacy === "dark" || legacy === "light"
        ? legacy
        : document.documentElement.getAttribute("data-theme") || "light";
    }
    if (theme !== "dark") theme = "light";
    skin = typeof stored.skin === "string" && stored.skin ? stored.skin : "default";
    uiState = { theme: theme, skin: skin };

    try {
      localStorage.setItem("mdr-ui", JSON.stringify(uiState));
      localStorage.removeItem("theme");
    } catch (ignoreMigration) {}

    return { theme: uiState.theme, skin: uiState.skin };
  }

  function setUi(patch) {
    var current = getUi();
    var next = {
      theme: current.theme,
      skin: current.skin
    };
    if (patch && patch.theme !== undefined) next.theme = patch.theme;
    if (patch && patch.skin !== undefined) next.skin = patch.skin;
    if (next.theme !== "dark") next.theme = "light";
    if (typeof next.skin !== "string" || !next.skin) next.skin = "default";
    uiState = next;
    try {
      localStorage.setItem("mdr-ui", JSON.stringify(uiState));
    } catch (ignoreWrite) {}
    applyUi(uiState);
    return { theme: uiState.theme, skin: uiState.skin };
  }

  function renderRail() {
    var rail = byId("mdr-rail");
    var i;
    var tool;
    var button;
    if (!rail) return;
    while (rail.firstChild) rail.removeChild(rail.firstChild);
    for (i = 0; i < tools.length; i += 1) {
      tool = tools[i];
      button = document.createElement("button");
      button.className = "mdr-rail-btn";
      button.type = "button";
      button.setAttribute("data-tool", tool.id);
      button.setAttribute("aria-label", tool.label);
      button.title = tool.label;
      button.textContent = tool.icon;
      if (tool.type === "panel") {
        button.setAttribute("aria-controls", "mdr-panel");
        button.setAttribute("aria-expanded", openId === tool.id ? "true" : "false");
        if (openId === tool.id) button.classList.add("is-active");
      }
      button.addEventListener("click", (function (registeredTool) {
        return function () {
          if (registeredTool.type === "panel") {
            if (openId === registeredTool.id) close();
            else open(registeredTool.id);
          } else if (typeof registeredTool.onClick === "function") {
            registeredTool.onClick(this);
          }
        };
      })(tool));
      rail.appendChild(button);
    }
  }

  function register(tool) {
    if (!tool) return;
    tools.push(tool);
    tools.sort(function (a, b) {
      return (a.order || 0) - (b.order || 0);
    });
    if (initialized) renderRail();
  }

  function panelFocus(panel, body, actions) {
    var selector = "button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex=\"-1\"])";
    var target;
    if (panel.contains(document.activeElement)) return;
    target = body.querySelector(selector) ||
      actions.querySelector(selector) ||
      byId("mdr-panel-close");
    if (target) {
      target.focus();
    } else {
      panel.setAttribute("tabindex", "-1");
      panel.focus();
    }
  }

  function open(id) {
    var tool = findTool(id);
    var panel;
    var title;
    var actions;
    var body;
    var button;
    if (!tool || tool.type !== "panel") return;
    // A panel is often opened from a click inside the article (the comment
    // bubble, a highlight). That click keeps bubbling to the document-level
    // outside-click handler, which would immediately close what we just
    // opened. Suppress it for the remainder of the current task.
    justOpened = true;
    setTimeout(function () {
      justOpened = false;
    }, 0);
    panel = byId("mdr-panel");
    title = byId("mdr-panel-title");
    actions = byId("mdr-panel-actions");
    body = byId("mdr-panel-body");
    if (!panel || !title || !actions || !body || !document.body) return;
    if (openId) close();

    openId = id;
    title.textContent = tool.label;
    while (actions.firstChild) actions.removeChild(actions.firstChild);
    while (body.firstChild) body.removeChild(body.firstChild);
    if (typeof tool.onOpen === "function") tool.onOpen(body, actions);

    panel.classList.add("is-open");
    panel.setAttribute("aria-hidden", "false");
    document.body.classList.add("mdr-panel-open");
    button = findToolButton(id);
    if (button) {
      button.classList.add("is-active");
      button.setAttribute("aria-expanded", "true");
    }
    panelFocus(panel, body, actions);
  }

  function close() {
    var id = openId;
    var tool;
    var panel;
    var title;
    var actions;
    var body;
    var button;
    if (!id) return;
    tool = findTool(id);
    panel = byId("mdr-panel");
    title = byId("mdr-panel-title");
    actions = byId("mdr-panel-actions");
    body = byId("mdr-panel-body");
    button = findToolButton(id);

    if (tool && typeof tool.onClose === "function") tool.onClose();
    openId = null;
    if (panel) {
      panel.classList.remove("is-open");
      panel.setAttribute("aria-hidden", "true");
    }
    if (document.body) document.body.classList.remove("mdr-panel-open");
    if (button) {
      button.classList.remove("is-active");
      button.setAttribute("aria-expanded", "false");
    }
    if (title) title.textContent = "";
    if (actions) while (actions.firstChild) actions.removeChild(actions.firstChild);
    if (body) while (body.firstChild) body.removeChild(body.firstChild);
    if (button && document.documentElement.contains(button)) button.focus();
  }

  function isOpen(id) {
    return openId === id;
  }

  function contentEl() {
    return byId("mdr-content");
  }

  function ready(cb) {
    if (typeof cb !== "function") return;
    if (initialized) cb();
    else readyCbs.push(cb);
  }

  function initialize() {
    var rail = byId("mdr-rail");
    var panel = byId("mdr-panel");
    var closeButton = byId("mdr-panel-close");
    var callbacks;
    var i;
    if (initialized) return;
    initialized = true;
    applyUi(getUi());

    if (rail) {
      renderRail();
      if (closeButton) closeButton.addEventListener("click", close);
      document.addEventListener("keydown", function (event) {
        if ((event.key === "Escape" || event.keyCode === 27) && openId) close();
      });
      document.addEventListener("click", function (event) {
        if (!openId || justOpened) return;
        if (rail.contains(event.target)) return;
        if (panel && panel.contains(event.target)) return;
        close();
      });
    }

    callbacks = readyCbs.slice();
    readyCbs.length = 0;
    for (i = 0; i < callbacks.length; i += 1) callbacks[i]();
  }

  window.MdrRail = {
    register: register,
    open: open,
    close: close,
    isOpen: isOpen,
    getUi: getUi,
    setUi: setUi,
    contentEl: contentEl,
    ready: ready
  };

  window.MdrRail.register({
    id: "theme",
    icon: "\uD83C\uDF13",
    label: "Toggle dark mode",
    order: 10,
    type: "button",
    onClick: function () {
      var ui = window.MdrRail.getUi();
      window.MdrRail.setUi({ theme: ui.theme === "dark" ? "light" : "dark" });
    }
  });

  var SKINS = [
    { id: "default", name: "Theme default", bg: "var(--bg)", fg: "var(--primary)" },
    { id: "github", name: "GitHub", bg: "#ffffff", fg: "#0969da" },
    { id: "solarized", name: "Solarized", bg: "#fdf6e3", fg: "#268bd2" },
    { id: "dracula", name: "Dracula", bg: "#282a36", fg: "#bd93f9" },
    { id: "nord", name: "Nord", bg: "#2e3440", fg: "#88c0d0" },
    { id: "sepia", name: "Sepia", bg: "#f4ecd8", fg: "#8b5a2b" }
  ];

  function buildSettings(body) {
    var ui = window.MdrRail.getUi();
    var appearanceTitle = document.createElement("h3");
    var themeGroup = document.createElement("div");
    var lightButton = document.createElement("button");
    var darkButton = document.createElement("button");
    var skinTitle = document.createElement("h3");
    var skinGroup = document.createElement("div");
    var radioButtons = [];

    function updateThemeButtons(theme) {
      var light = theme === "light";
      lightButton.setAttribute("aria-pressed", light ? "true" : "false");
      darkButton.setAttribute("aria-pressed", light ? "false" : "true");
      lightButton.className = light ? "mdr-btn is-primary" : "mdr-btn";
      darkButton.className = light ? "mdr-btn" : "mdr-btn is-primary";
    }

    function selectSkin(index, moveFocus) {
      var i;
      window.MdrRail.setUi({ skin: SKINS[index].id });
      for (i = 0; i < radioButtons.length; i += 1) {
        radioButtons[i].setAttribute("aria-checked", i === index ? "true" : "false");
        radioButtons[i].tabIndex = i === index ? 0 : -1;
      }
      if (moveFocus) radioButtons[index].focus();
    }

    appearanceTitle.textContent = "Appearance";
    themeGroup.setAttribute("role", "group");
    themeGroup.setAttribute("aria-label", "Appearance");
    themeGroup.style.display = "flex";
    themeGroup.style.gap = ".5rem";

    lightButton.type = "button";
    lightButton.textContent = "Light";
    lightButton.addEventListener("click", function () {
      window.MdrRail.setUi({ theme: "light" });
      updateThemeButtons("light");
    });
    darkButton.type = "button";
    darkButton.textContent = "Dark";
    darkButton.addEventListener("click", function () {
      window.MdrRail.setUi({ theme: "dark" });
      updateThemeButtons("dark");
    });
    updateThemeButtons(ui.theme);
    themeGroup.appendChild(lightButton);
    themeGroup.appendChild(darkButton);

    skinTitle.textContent = "Skin";
    skinGroup.setAttribute("role", "radiogroup");
    skinGroup.setAttribute("aria-label", "Skin");

    SKINS.forEach(function (skin, index) {
      var option = document.createElement("button");
      var swatch = document.createElement("span");
      var name = document.createElement("span");
      var selected = skin.id === ui.skin;

      option.type = "button";
      option.className = "mdr-skin-option";
      option.setAttribute("role", "radio");
      option.setAttribute("aria-checked", selected ? "true" : "false");
      option.tabIndex = selected ? 0 : -1;
      swatch.className = "mdr-swatch";
      swatch.setAttribute("aria-hidden", "true");
      swatch.style.background = "linear-gradient(135deg, " +
        skin.bg + " 50%, " + skin.fg + " 50%)";
      name.textContent = skin.name;
      option.appendChild(swatch);
      option.appendChild(name);
      option.addEventListener("click", function () {
        selectSkin(index, false);
      });
      option.addEventListener("keydown", function (event) {
        var next = index;
        var key = event.key;
        if (key === "ArrowRight" || key === "ArrowDown" ||
            event.keyCode === 39 || event.keyCode === 40) {
          next = (index + 1) % SKINS.length;
        } else if (key === "ArrowLeft" || key === "ArrowUp" ||
                   event.keyCode === 37 || event.keyCode === 38) {
          next = (index + SKINS.length - 1) % SKINS.length;
        } else if (key === "Home" || event.keyCode === 36) {
          next = 0;
        } else if (key === "End" || event.keyCode === 35) {
          next = SKINS.length - 1;
        } else {
          return;
        }
        event.preventDefault();
        selectSkin(next, true);
      });
      radioButtons.push(option);
      skinGroup.appendChild(option);
    });

    if (!radioButtons.some(function (button) {
      return button.getAttribute("aria-checked") === "true";
    })) {
      selectSkin(0, false);
    }

    body.appendChild(appearanceTitle);
    body.appendChild(themeGroup);
    body.appendChild(skinTitle);
    body.appendChild(skinGroup);
  }

  window.MdrRail.register({
    id: "settings",
    icon: "\u2699",
    label: "Settings",
    order: 20,
    type: "panel",
    onOpen: function (body) {
      buildSettings(body);
    }
  });

  var sourceState = {
    text: null,
    shown: false,
    rendered: null,
    pre: null,
    loading: false
  };

  function sourceButton() {
    return findToolButton("source");
  }

  function dispatchSourceEvent(name) {
    document.dispatchEvent(new CustomEvent(name));
  }

  function showSource(button) {
    var content = contentEl();
    var i;
    if (!content || sourceState.shown || sourceState.text === null) return;

    if (!sourceState.rendered) {
      sourceState.rendered = Array.prototype.slice.call(content.childNodes);
    }
    for (i = 0; i < sourceState.rendered.length; i += 1) {
      if (sourceState.rendered[i].parentNode === content) {
        content.removeChild(sourceState.rendered[i]);
      }
    }
    if (!sourceState.pre) {
      sourceState.pre = document.createElement("pre");
      sourceState.pre.className = "mdr-source";
    }
    sourceState.pre.textContent = sourceState.text;
    content.appendChild(sourceState.pre);
    sourceState.shown = true;
    if (document.body) document.body.classList.add("mdr-source-mode");
    if (button) button.classList.add("is-active");
    dispatchSourceEvent("mdr:source-shown");
  }

  function hideSource(button) {
    var content = contentEl();
    var i;
    if (!content || !sourceState.shown) return;
    if (sourceState.pre && sourceState.pre.parentNode === content) {
      content.removeChild(sourceState.pre);
    }
    for (i = 0; i < sourceState.rendered.length; i += 1) {
      content.appendChild(sourceState.rendered[i]);
    }
    sourceState.shown = false;
    if (document.body) document.body.classList.remove("mdr-source-mode");
    if (button) button.classList.remove("is-active");
    dispatchSourceEvent("mdr:source-hidden");
  }

  function showSourceError() {
    var content = contentEl();
    var error;
    if (!content || !content.parentNode) return;
    error = document.createElement("div");
    error.className = "mdr-empty";
    error.textContent = "Could not load source.";
    content.parentNode.insertBefore(error, content);
    window.setTimeout(function () {
      if (error.parentNode) error.parentNode.removeChild(error);
    }, 4000);
  }

  function toggleSource(button) {
    if (sourceState.shown) {
      hideSource(button);
      return;
    }
    if (sourceState.text !== null) {
      showSource(button);
      return;
    }
    if (sourceState.loading || !contentEl()) return;

    sourceState.loading = true;
    button.setAttribute("aria-busy", "true");
    fetch(location.pathname + "?raw=1", { credentials: "same-origin" })
      .then(function (response) {
        var contentType = (response.headers.get("content-type") || "").toLowerCase();
        if (!response.ok || contentType.indexOf("text/plain") !== 0) {
          location.reload();
          return null;
        }
        return response.text();
      })
      .then(function (text) {
        sourceState.loading = false;
        button.removeAttribute("aria-busy");
        if (text === null) return;
        sourceState.text = text;
        showSource(sourceButton() || button);
      }, function () {
        sourceState.loading = false;
        button.removeAttribute("aria-busy");
        showSourceError();
      });
  }

  window.MdrRail.register({
    id: "source",
    icon: "</>",
    label: "Toggle source",
    order: 40,
    type: "button",
    onClick: function (button) {
      toggleSource(button);
    }
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initialize);
  } else {
    initialize();
  }
})();
