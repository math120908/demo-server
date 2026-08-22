// UMD: browser global MdrComments; CommonJS require for pure-function tests.
// Anchoring logic ported from chrome-swiss-knife/markdown-reader/src/comments.js.
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.MdrComments = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  var AFFIX = 32;
  var MIN_EXACT = 3;
  var initialized = false;

  function captureQuote(fullText, start, end) {
    return {
      exact: fullText.slice(start, end),
      prefix: fullText.slice(Math.max(0, start - AFFIX), start),
      suffix: fullText.slice(end, Math.min(fullText.length, end + AFFIX)),
    };
  }

  function affixScore(fullText, start, end, quote) {
    var score = 0;
    var prefix = quote.prefix || "";
    var suffix = quote.suffix || "";
    var i;
    for (i = 1; i <= prefix.length && start - i >= 0; i += 1) {
      if (fullText[start - i] !== prefix[prefix.length - i]) break;
      score += 1;
    }
    for (i = 0; i < suffix.length && end + i < fullText.length; i += 1) {
      if (fullText[end + i] !== suffix[i]) break;
      score += 1;
    }
    return score;
  }

  function resolveQuote(fullText, quote) {
    var exact = quote && quote.exact;
    var hits = [];
    var index;
    var best;
    var bestScore;
    var i;
    var score;
    if (!exact) return null;
    index = fullText.indexOf(exact);
    while (index !== -1) {
      hits.push(index);
      index = fullText.indexOf(exact, index + 1);
    }
    if (!hits.length) return null;
    if (hits.length === 1) {
      return { start: hits[0], end: hits[0] + exact.length };
    }
    best = hits[0];
    bestScore = -1;
    for (i = 0; i < hits.length; i += 1) {
      score = affixScore(fullText, hits[i], hits[i] + exact.length, quote);
      if (score > bestScore) {
        best = hits[i];
        bestScore = score;
      }
    }
    return { start: best, end: best + exact.length };
  }

  function buildTextIndex(rootEl) {
    var walker = document.createTreeWalker(rootEl, NodeFilter.SHOW_TEXT, null);
    var text = "";
    var nodes = [];
    var node;
    var start;
    while ((node = walker.nextNode())) {
      start = text.length;
      text += node.nodeValue;
      nodes.push({ node: node, start: start, end: text.length });
    }
    return { text: text, nodes: nodes };
  }

  function domPointToOffset(index, node, nodeOffset) {
    var i;
    for (i = 0; i < index.nodes.length; i += 1) {
      if (index.nodes[i].node === node) return index.nodes[i].start + nodeOffset;
    }
    return null;
  }

  function wrapRange(index, start, end, id) {
    var spans = [];
    var i;
    var segment;
    var segmentStart;
    var segmentEnd;
    var target;
    var localStart;
    var localLength;
    var span;
    for (i = 0; i < index.nodes.length; i += 1) {
      segment = index.nodes[i];
      segmentStart = Math.max(start, segment.start);
      segmentEnd = Math.min(end, segment.end);
      if (segmentStart >= segmentEnd) continue;
      target = segment.node;
      localStart = segmentStart - segment.start;
      localLength = segmentEnd - segmentStart;
      if (localStart > 0) target = target.splitText(localStart);
      if (target.nodeValue.length > localLength) target.splitText(localLength);
      span = document.createElement("span");
      span.className = "mdr-comment-hl";
      span.setAttribute("data-id", id);
      target.parentNode.insertBefore(span, target);
      span.appendChild(target);
      spans.push(span);
    }
    return spans;
  }

  function storageKey() {
    return "mdr-comments:" + location.pathname;
  }

  function loadComments() {
    try {
      var value = JSON.parse(localStorage.getItem(storageKey()) || "[]");
      return Array.isArray(value) ? value : [];
    } catch (e) {
      return [];
    }
  }

  function storableComment(comment) {
    return {
      id: comment.id,
      quote: comment.quote,
      text: comment.text,
      createdAt: comment.createdAt,
      updatedAt: comment.updatedAt,
    };
  }

  function saveComments(list) {
    var stored = [];
    var i;
    for (i = 0; i < list.length; i += 1) {
      stored.push(storableComment(list[i]));
    }
    try {
      localStorage.setItem(storageKey(), JSON.stringify(stored));
    } catch (e) {}
  }

  function clearHighlights(rootEl) {
    var spans = rootEl.querySelectorAll("span.mdr-comment-hl");
    var i;
    var span;
    var parent;
    for (i = 0; i < spans.length; i += 1) {
      span = spans[i];
      parent = span.parentNode;
      if (!parent) continue;
      while (span.firstChild) parent.insertBefore(span.firstChild, span);
      parent.removeChild(span);
      parent.normalize();
    }
  }

  function renderHighlights(rootEl, comments) {
    var pristine;
    var resolved = [];
    var i;
    var comment;
    var location;
    var index;
    clearHighlights(rootEl);
    pristine = buildTextIndex(rootEl).text;
    for (i = 0; i < comments.length; i += 1) {
      comment = comments[i];
      location = resolveQuote(pristine, comment.quote);
      comment.orphan = !location;
      if (location) {
        resolved.push({ comment: comment, location: location, order: i });
      }
    }
    resolved.sort(function (a, b) {
      var lengthDifference =
        b.location.end - b.location.start - (a.location.end - a.location.start);
      return lengthDifference || a.order - b.order;
    });
    for (i = 0; i < resolved.length; i += 1) {
      index = buildTextIndex(rootEl);
      wrapRange(
        index,
        resolved[i].location.start,
        resolved[i].location.end,
        resolved[i].comment.id
      );
    }
    return resolved;
  }

  function newCommentId() {
    return "c_" + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
  }

  function element(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function init(rail) {
    var rootEl;
    var comments;
    var pending = null;
    var selectionButton = null;
    var pendingRange = null;
    var panelBody = null;
    var panelActions = null;
    var sourceShown = false;

    if (initialized || !rail || !rail.contentEl) return;
    rootEl = rail.contentEl();
    if (!rootEl) return;
    initialized = true;
    comments = loadComments();
    renderHighlights(rootEl, comments);

    function removeSelectionButton() {
      if (selectionButton && selectionButton.parentNode) {
        selectionButton.parentNode.removeChild(selectionButton);
      }
      selectionButton = null;
      pendingRange = null;
    }

    function flash(id, scrollHighlight) {
      var highlights = rootEl.querySelectorAll(
        'span.mdr-comment-hl[data-id="' + id + '"]'
      );
      var item = panelBody && panelBody.querySelector(
        '.mdr-comment-item[data-id="' + id + '"]'
      );
      var i;
      if (scrollHighlight && highlights.length) {
        highlights[0].scrollIntoView({ behavior: "smooth", block: "center" });
      } else if (item) {
        item.scrollIntoView({ block: "nearest" });
      }
      for (i = 0; i < highlights.length; i += 1) {
        highlights[i].classList.add("is-active");
      }
      if (item) item.classList.add("is-active");
      setTimeout(function () {
        var current = rootEl.querySelectorAll(
          'span.mdr-comment-hl[data-id="' + id + '"]'
        );
        var currentItem = panelBody && panelBody.querySelector(
          '.mdr-comment-item[data-id="' + id + '"]'
        );
        var j;
        for (j = 0; j < current.length; j += 1) {
          current[j].classList.remove("is-active");
        }
        if (currentItem) currentItem.classList.remove("is-active");
      }, 1500);
    }

    function persistAndRefreshHighlights() {
      saveComments(comments);
      renderHighlights(rootEl, comments);
    }

    function exportToTab() {
      var exported = [];
      var i;
      var payload;
      var blob;
      var url;
      for (i = 0; i < comments.length; i += 1) {
        exported.push(storableComment(comments[i]));
      }
      payload = {
        version: 1,
        file: location.pathname,
        exportedAt: Math.floor(Date.now() / 1000),
        comments: exported,
      };
      blob = new Blob([JSON.stringify(payload, null, 2)], {
        type: "application/json",
      });
      url = URL.createObjectURL(blob);
      window.open(url, "_blank", "noopener");
      setTimeout(function () {
        URL.revokeObjectURL(url);
      }, 60000);
    }

    function renderComposer(body) {
      var textarea = element("textarea", "mdr-textarea");
      var actions = element("div", "mdr-comment-actions");
      var save = element("button", "mdr-btn is-primary", "Save");
      var cancel = element("button", "mdr-btn", "Cancel");
      textarea.setAttribute("placeholder", "Write a comment\u2026");
      actions.appendChild(save);
      actions.appendChild(cancel);
      body.appendChild(textarea);
      body.appendChild(actions);
      save.addEventListener("click", function () {
        var text = textarea.value.replace(/^\s+|\s+$/g, "");
        var now;
        if (!text) {
          textarea.focus();
          return;
        }
        now = Math.floor(Date.now() / 1000);
        comments.push({
          id: newCommentId(),
          quote: pending.quote,
          text: text,
          createdAt: now,
          updatedAt: now,
        });
        pending = null;
        persistAndRefreshHighlights();
        renderPanel();
      });
      cancel.addEventListener("click", function () {
        pending = null;
        renderPanel();
      });
      setTimeout(function () {
        textarea.focus();
      }, 0);
    }

    function unwrapHighlight(id) {
      var spans = rootEl.querySelectorAll(
        'span.mdr-comment-hl[data-id="' + id + '"]'
      );
      var i;
      var parent;
      for (i = 0; i < spans.length; i += 1) {
        parent = spans[i].parentNode;
        if (!parent) continue;
        while (spans[i].firstChild) {
          parent.insertBefore(spans[i].firstChild, spans[i]);
        }
        parent.removeChild(spans[i]);
        parent.normalize();
      }
    }

    function deleteComment(id) {
      var next = [];
      var i;
      if (!window.confirm("Delete this comment?")) return;
      for (i = 0; i < comments.length; i += 1) {
        if (comments[i].id !== id) next.push(comments[i]);
      }
      comments = next;
      unwrapHighlight(id);
      saveComments(comments);
      renderPanel();
    }

    function editComment(item, comment) {
      var textarea = element("textarea", "mdr-textarea");
      var actions = element("div", "mdr-comment-actions");
      var save = element("button", "mdr-btn is-primary", "Save");
      var cancel = element("button", "mdr-btn", "Cancel");
      textarea.value = comment.text;
      actions.appendChild(save);
      actions.appendChild(cancel);
      item.textContent = "";
      item.appendChild(element("div", "mdr-comment-quote", comment.quote.exact));
      item.appendChild(textarea);
      item.appendChild(actions);
      textarea.focus();
      save.addEventListener("click", function (event) {
        var text = textarea.value.replace(/^\s+|\s+$/g, "");
        event.stopPropagation();
        if (!text) {
          textarea.focus();
          return;
        }
        comment.text = text;
        comment.updatedAt = Math.floor(Date.now() / 1000);
        saveComments(comments);
        renderPanel();
      });
      cancel.addEventListener("click", function (event) {
        event.stopPropagation();
        renderPanel();
      });
    }

    function renderCommentItem(comment) {
      var item = element("div", "mdr-comment-item");
      var actions = element("div", "mdr-comment-actions");
      var edit = element("button", "mdr-btn", "Edit");
      var remove = element("button", "mdr-btn", "Delete");
      item.setAttribute("data-id", comment.id);
      if (comment.orphan) item.classList.add("is-orphan");
      item.appendChild(
        element("div", "mdr-comment-quote", comment.quote.exact || "")
      );
      item.appendChild(element("div", "mdr-comment-text", comment.text || ""));
      if (comment.orphan) {
        item.appendChild(element("div", null, "anchor not found on this page"));
      }
      actions.appendChild(edit);
      actions.appendChild(remove);
      item.appendChild(actions);
      item.addEventListener("click", function () {
        if (!comment.orphan) flash(comment.id, true);
      });
      edit.addEventListener("click", function (event) {
        event.stopPropagation();
        editComment(item, comment);
      });
      remove.addEventListener("click", function (event) {
        event.stopPropagation();
        deleteComment(comment.id);
      });
      return item;
    }

    function renderPanel() {
      var exportButton;
      var ordered;
      var i;
      if (!panelBody || !panelActions) return;
      panelBody.textContent = "";
      panelActions.textContent = "";
      exportButton = element("button", "mdr-btn", "\u29C9 To tab");
      exportButton.title = "Open the comment JSON in a new tab";
      exportButton.addEventListener("click", exportToTab);
      panelActions.appendChild(exportButton);
      if (pending) renderComposer(panelBody);
      ordered = comments.slice();
      ordered.sort(function (a, b) {
        return (b.createdAt || 0) - (a.createdAt || 0);
      });
      if (!ordered.length && !pending) {
        panelBody.appendChild(
          element(
            "div",
            "mdr-empty",
            "No comments yet. Select some text to add one."
          )
        );
        return;
      }
      for (i = 0; i < ordered.length; i += 1) {
        panelBody.appendChild(renderCommentItem(ordered[i]));
      }
    }

    function capturePending(range) {
      var index = buildTextIndex(rootEl);
      var start = domPointToOffset(index, range.startContainer, range.startOffset);
      var end = domPointToOffset(index, range.endContainer, range.endOffset);
      var selectedText;
      var fallback;
      if (start === null || end === null || end <= start) {
        selectedText = range.toString();
        fallback = index.text.indexOf(selectedText);
        if (fallback === -1) return;
        start = fallback;
        end = fallback + selectedText.length;
      }
      if (end - start < MIN_EXACT) return;
      pending = { quote: captureQuote(index.text, start, end) };
      removeSelectionButton();
      rail.open("comments");
    }

    function showSelectionButton() {
      var selection;
      var range;
      var text;
      var rect;
      if (sourceShown) {
        removeSelectionButton();
        return;
      }
      selection = window.getSelection();
      if (!selection || selection.isCollapsed || !selection.rangeCount) {
        removeSelectionButton();
        return;
      }
      range = selection.getRangeAt(0);
      text = selection.toString();
      if (
        text.length < MIN_EXACT ||
        !rootEl.contains(range.startContainer) ||
        !rootEl.contains(range.endContainer)
      ) {
        removeSelectionButton();
        return;
      }
      rect = range.getBoundingClientRect();
      removeSelectionButton();
      pendingRange = range.cloneRange();
      selectionButton = element("button", "mdr-selection-btn", "\uD83D\uDCAC");
      selectionButton.type = "button";
      selectionButton.setAttribute("aria-label", "Add comment");
      selectionButton.style.left = rect.right + window.scrollX + "px";
      selectionButton.style.top = rect.bottom + window.scrollY + "px";
      selectionButton.addEventListener("mousedown", function (event) {
        event.preventDefault();
      });
      selectionButton.addEventListener("click", function () {
        var rangeToCapture = pendingRange;
        if (rangeToCapture) capturePending(rangeToCapture);
      });
      document.body.appendChild(selectionButton);
    }

    rootEl.addEventListener("mouseup", function () {
      setTimeout(showSelectionButton, 0);
    });
    rootEl.addEventListener("keyup", function () {
      setTimeout(showSelectionButton, 0);
    });
    rootEl.addEventListener("click", function (event) {
      var node = event.target;
      var id;
      while (node && node !== rootEl) {
        if (node.classList && node.classList.contains("mdr-comment-hl")) {
          id = node.getAttribute("data-id");
          rail.open("comments");
          setTimeout(function () {
            flash(id, false);
          }, 0);
          return;
        }
        node = node.parentNode;
      }
    });

    document.addEventListener("mdr:source-shown", function () {
      sourceShown = true;
      removeSelectionButton();
    });
    document.addEventListener("mdr:source-hidden", function () {
      sourceShown = false;
      renderPanel();
    });

    rail.register({
      id: "comments",
      icon: "\uD83D\uDCAC",
      label: "Comments",
      order: 30,
      type: "panel",
      onOpen: function (body, actions) {
        panelBody = body;
        panelActions = actions;
        renderPanel();
      },
      onClose: function () {
        panelBody = null;
        panelActions = null;
      },
    });
  }

  return {
    captureQuote: captureQuote,
    affixScore: affixScore,
    resolveQuote: resolveQuote,
    buildTextIndex: buildTextIndex,
    domPointToOffset: domPointToOffset,
    wrapRange: wrapRange,
    newCommentId: newCommentId,
    storageKey: storageKey,
    loadComments: loadComments,
    saveComments: saveComments,
    clearHighlights: clearHighlights,
    renderHighlights: renderHighlights,
    init: init,
    MIN_EXACT: MIN_EXACT,
  };
});

(function () {
  if (typeof window === "undefined" || !window.MdrRail) return;
  window.MdrRail.ready(function () {
    window.MdrComments.init(window.MdrRail);
  });
})();
