/**
 * Shared GLP Presentation Mode
 * Canvas-based fullscreen presentation for DATA / SOP / PRESENTATION files.
 * Used by GLP Vision (researcher/supervisor) and PI Dashboard.
 */
(function () {
  'use strict';

  var presDoc = null;
  var presPage = 1;
  var presTotal = 0;
  var presPointerActive = false;
  var _pdfjsLib = null;
  var _cssInjected = false;

  function injectCSS() {
    if (_cssInjected) return;
    _cssInjected = true;
    var s = document.createElement('style');
    s.textContent =
      '#gvPresOverlay{position:fixed;inset:0;background:#000;z-index:100001;display:none;align-items:center;justify-content:center;flex-direction:column;}' +
      '#gvPresOverlay.active{display:flex;}' +
      '#gvPresCanvas{max-width:100vw;max-height:100vh;display:block;}' +
      '#gvPresPageIndicator{position:fixed;bottom:16px;left:50%;transform:translateX(-50%);color:rgba(255,255,255,0.35);font-size:13px;font-weight:600;pointer-events:none;z-index:100002;}' +
      '#gvPresPointerBtn{position:fixed;bottom:16px;right:16px;z-index:100002;width:36px;height:36px;border-radius:50%;background:rgba(255,255,255,0.15);border:1px solid rgba(255,255,255,0.25);color:rgba(255,255,255,0.6);font-size:16px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:background 0.15s;}' +
      '#gvPresPointerBtn:hover{background:rgba(255,255,255,0.25);}' +
      '#gvPresPointerBtn.active{background:rgba(255,255,255,0.35);color:#fff;}' +
      '.gv-pres-pointer{cursor:crosshair!important;}';
    document.head.appendChild(s);
  }

  function ensureOverlay() {
    var o = document.getElementById('gvPresOverlay');
    if (o) return o;
    injectCSS();
    o = document.createElement('div');
    o.id = 'gvPresOverlay';
    o.innerHTML =
      '<canvas id="gvPresCanvas"></canvas>' +
      '<div id="gvPresPageIndicator"></div>' +
      '<button id="gvPresPointerBtn" onclick="gvTogglePointer()" title="Toggle pointer (P)">&#9678;</button>';
    document.body.appendChild(o);
    return o;
  }

  async function getPdfLib() {
    if (_pdfjsLib) return _pdfjsLib;
    _pdfjsLib = await import('/pdfjs/build/pdf.mjs');
    _pdfjsLib.GlobalWorkerOptions.workerSrc = '/pdfjs/build/pdf.worker.mjs';
    return _pdfjsLib;
  }

  async function renderPage() {
    if (!presDoc) return;
    var canvas = document.getElementById('gvPresCanvas');
    var ctx = canvas.getContext('2d');
    var page = await presDoc.getPage(presPage);

    var vw = window.innerWidth, vh = window.innerHeight;
    var uv = page.getViewport({ scale: 1 });
    var scale = Math.min(vw / uv.width, vh / uv.height);
    var vp = page.getViewport({ scale: scale });

    canvas.width = vp.width;
    canvas.height = vp.height;
    canvas.style.width = vp.width + 'px';
    canvas.style.height = vp.height + 'px';

    await page.render({ canvasContext: ctx, viewport: vp }).promise;
    document.getElementById('gvPresPageIndicator').textContent = presPage + ' / ' + presTotal;
  }

  function nav(dir) {
    var next = presPage + dir;
    if (next >= 1 && next <= presTotal) { presPage = next; renderPage(); }
  }

  function keyHandler(e) {
    var ov = document.getElementById('gvPresOverlay');
    if (!ov || !ov.classList.contains('active')) return;
    switch (e.key) {
      case 'ArrowRight':
      case ' ':
        if (e.shiftKey && e.key === ' ') { nav(-1); } else { nav(1); }
        e.preventDefault(); break;
      case 'ArrowLeft':
        nav(-1); e.preventDefault(); break;
      case 'Home':
        presPage = 1; renderPage(); e.preventDefault(); break;
      case 'End':
        presPage = presTotal; renderPage(); e.preventDefault(); break;
      case 'Escape':
        exitPresentation(); e.preventDefault(); break;
      case 'p': case 'P':
        togglePointer(); e.preventDefault(); break;
    }
  }

  function fsChange() {
    if (!document.fullscreenElement && !document.webkitFullscreenElement) {
      exitPresentation();
    }
  }

  function togglePointer() {
    presPointerActive = !presPointerActive;
    var canvas = document.getElementById('gvPresCanvas');
    var btn = document.getElementById('gvPresPointerBtn');
    canvas.classList.toggle('gv-pres-pointer', presPointerActive);
    btn.classList.toggle('active', presPointerActive);
  }

  async function enterPresentation(fileUrl) {
    if (!fileUrl) return;
    var overlay = ensureOverlay();
    var canvas = document.getElementById('gvPresCanvas');

    overlay.classList.add('active');
    presPage = 1;
    presPointerActive = false;
    document.getElementById('gvPresPointerBtn').classList.remove('active');
    canvas.classList.remove('gv-pres-pointer');

    try {
      if (overlay.requestFullscreen) overlay.requestFullscreen();
      else if (overlay.webkitRequestFullscreen) overlay.webkitRequestFullscreen();

      var lib = await getPdfLib();
      presDoc = await lib.getDocument(fileUrl).promise;
      presTotal = presDoc.numPages;
      document.getElementById('gvPresPageIndicator').textContent = presPage + ' / ' + presTotal;
      await renderPage();
    } catch (err) {
      console.error('[Presentation] Load error:', err);
      exitPresentation();
    }

    document.addEventListener('keydown', keyHandler);
    document.addEventListener('fullscreenchange', fsChange);
    document.addEventListener('webkitfullscreenchange', fsChange);
  }

  function exitPresentation() {
    var overlay = document.getElementById('gvPresOverlay');
    if (overlay) overlay.classList.remove('active');
    document.removeEventListener('keydown', keyHandler);
    document.removeEventListener('fullscreenchange', fsChange);
    document.removeEventListener('webkitfullscreenchange', fsChange);

    if (document.fullscreenElement || document.webkitFullscreenElement) {
      if (document.exitFullscreen) document.exitFullscreen();
      else if (document.webkitExitFullscreen) document.webkitExitFullscreen();
    }

    presDoc = null;
    presPointerActive = false;
  }

  // Global API
  window.gvPresEnter = enterPresentation;
  window.gvExitPresentation = exitPresentation;
  window.gvTogglePointer = togglePointer;
})();
