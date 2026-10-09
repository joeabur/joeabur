/* Portfolio behaviour — vanilla JS, no dependencies. */
(function () {
  'use strict';

  /* ---------- Footer year ---------- */
  var year = document.getElementById('year');
  if (year) year.textContent = new Date().getFullYear();

  /* ---------- Mobile navigation ---------- */
  var toggle = document.querySelector('.nav-toggle');
  var nav = document.getElementById('primary-nav');
  function setMenu(open) {
    toggle.setAttribute('aria-expanded', String(open));
    nav.classList.toggle('open', open);
  }
  if (toggle && nav) {
    toggle.addEventListener('click', function () {
      setMenu(toggle.getAttribute('aria-expanded') !== 'true');
    });
    nav.addEventListener('click', function (e) {
      if (e.target.closest('a')) setMenu(false);
    });
  }
  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') return;
    if (toggle && toggle.getAttribute('aria-expanded') === 'true') { setMenu(false); toggle.focus(); }
    var active = document.activeElement;
    if (active && active.classList && active.classList.contains('term')) active.blur();
  });

  /* ---------- Current section in nav ---------- */
  var links = Array.prototype.slice.call(document.querySelectorAll('.nav a[href^="#"]'));
  if ('IntersectionObserver' in window) {
    var spy = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        links.forEach(function (a) {
          var on = a.getAttribute('href') === '#' + entry.target.id;
          a.classList.toggle('active', on);
          if (on) a.setAttribute('aria-current', 'true'); else a.removeAttribute('aria-current');
        });
      });
    }, { rootMargin: '-45% 0px -50% 0px' });
    document.querySelectorAll('main section[id]').forEach(function (s) { spy.observe(s); });
  }

  /* ---------- Back to top ---------- */
  var toTop = document.querySelector('.to-top');
  function onScroll() {
    var show = window.scrollY > 700;
    if (toTop) toTop.hidden = !show;
    if (window.scrollY < 200) {
      links.forEach(function (a) { a.classList.remove('active'); a.removeAttribute('aria-current'); });
    }
  }
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();

  /* ---------- Accessible tabs (skills + steppers) ---------- */
  document.querySelectorAll('[data-tabs]').forEach(function (root) {
    var tabs = Array.prototype.slice.call(root.querySelectorAll('[role="tab"]'));
    var panels = tabs.map(function (t) { return document.getElementById(t.getAttribute('aria-controls')); });

    function select(i, focus) {
      tabs.forEach(function (t, n) {
        var on = n === i;
        t.setAttribute('aria-selected', String(on));
        t.tabIndex = on ? 0 : -1;
        if (panels[n]) panels[n].hidden = !on;
      });
      if (focus) tabs[i].focus();
    }
    tabs.forEach(function (t, i) {
      t.addEventListener('click', function () { select(i, false); });
      t.addEventListener('keydown', function (e) {
        var next = null;
        if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next = (i + 1) % tabs.length;
        else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') next = (i - 1 + tabs.length) % tabs.length;
        else if (e.key === 'Home') next = 0;
        else if (e.key === 'End') next = tabs.length - 1;
        if (next !== null) { e.preventDefault(); select(next, true); }
      });
    });
    var start = tabs.findIndex(function (t) { return t.getAttribute('aria-selected') === 'true'; });
    select(start < 0 ? 0 : start, false);
  });

  // Jump links such as "#lifecycle" land on blocks that are always visible,
  // but links into a skill panel from other panels keep working because
  // panels are only hidden by this script.

  /* ---------- Conceptual architecture details ---------- */
  var archDetail = document.getElementById('arch-detail');
  var ARCH = {
    cloudtrail: ['AWS CloudTrail', 'Records API activity in an AWS account: which identity called which API, when, and from where.', 'It is the primary evidence for “who changed what” in a cloud investigation, so gaps or delays here weaken every later stage.'],
    cloudwatch: ['AWS CloudWatch', 'Collects logs, metrics and alarms from AWS resources and applications.', 'Adds operational and application context to audit events, and is a common place where log delivery problems show up.'],
    k8s: ['Kubernetes & containers', 'Cluster and workload logs and events describe how workloads are scheduled, configured and behave.', 'Containers are short-lived; if their logs are not shipped somewhere durable, the evidence disappears with the container.'],
    falcon: ['CrowdStrike Falcon', 'Endpoint and workload detection and response: behavioural detections, host investigation and containment actions.', 'Gives the process-level view that cloud audit logs cannot, and a way to contain a host during an incident.'],
    cloudflare: ['Cloudflare', 'Sits at the network edge in front of web applications, providing protection and visibility of inbound traffic.', 'Shows attacks and abnormal traffic before they reach the application and adds context to application-layer alerts.'],
    pipeline: ['Log forwarding & time synchronisation', 'The transport layer that moves events from sources into the SIEM, with accurate timestamps.', 'If a source goes silent or a clock drifts, detections quietly fail and timelines can’t be trusted. Monitoring ingestion gaps, pipeline outages and NTP drift is part of my current role.'],
    siem: ['FortiSIEM', 'Parses incoming events, correlates them across sources using rules, and raises alerts.', 'This is where signals from different tools become one story. I develop and tune detection rules here to cut false positives and improve alert quality.'],
    triage: ['Alert triage & investigation', 'An analyst reviews each alert, gathers context from the sources above and decides whether to dismiss, tune the rule, or escalate.', 'Human judgement is what turns alerts into incidents — and the reasons for dismissals are the raw material for better rules.'],
    ir: ['Incident response & post-incident review', 'Playbook-guided containment support and escalation, followed by a review and reporting.', 'The review closes the loop: findings change detection rules, logging standards and playbooks. I maintain playbooks, write incident reports and run tabletop exercises.']
  };
  var archRoot = document.querySelector('[data-arch]');
  if (archRoot && archDetail) {
    archRoot.addEventListener('click', function (e) {
      var node = e.target.closest('.node');
      if (!node) return;
      var d = ARCH[node.getAttribute('data-node')];
      if (!d) return;
      archRoot.querySelectorAll('.node').forEach(function (n) { n.setAttribute('aria-pressed', String(n === node)); });
      archDetail.textContent = '';
      var h = document.createElement('h4');
      h.textContent = d[0];
      archDetail.appendChild(h);
      [['What it does. ', d[1]], ['Why it matters here. ', d[2]]].forEach(function (pair) {
        var p = document.createElement('p');
        var strong = document.createElement('strong');
        strong.textContent = pair[0];
        p.appendChild(strong);
        p.appendChild(document.createTextNode(pair[1]));
        archDetail.appendChild(p);
      });
      var note = document.createElement('p');
      note.className = 'muted small';
      note.textContent = 'Conceptual diagram — not a record of any specific deployment.';
      archDetail.appendChild(note);
    });
  }

  /* ---------- Project screenshots (appear only when the image file exists) ---------- */
  var lightbox = document.getElementById('lightbox');
  document.querySelectorAll('[data-shot]').forEach(function (slot) {
    var src = slot.getAttribute('data-shot');
    var title = slot.getAttribute('data-title') || 'Project';
    var probe = new Image();
    probe.onload = function () {
      var fig = document.createElement('figure');
      fig.className = 'shot';
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'shot-btn';
      btn.setAttribute('aria-label', 'Enlarge screenshot: ' + title);
      var img = document.createElement('img');
      img.src = src;
      img.alt = 'Screenshot of ' + title;
      img.loading = 'lazy';
      btn.appendChild(img);
      var cap = document.createElement('figcaption');
      cap.textContent = 'Screenshot: ' + title + ' (click to enlarge)';
      fig.appendChild(btn);
      fig.appendChild(cap);
      slot.replaceWith(fig);
      if (lightbox && typeof lightbox.showModal === 'function') {
        btn.addEventListener('click', function () {
          lightbox.querySelector('img').src = src;
          lightbox.querySelector('img').alt = img.alt;
          lightbox.querySelector('.lb-cap').textContent = title;
          lightbox.showModal();
        });
      }
    };
    probe.src = src;
  });
  if (lightbox) {
    lightbox.addEventListener('click', function (e) { if (e.target === lightbox) lightbox.close(); });
  }

  /* ---------- Project filters ---------- */
  var chips = document.querySelectorAll('.filters .chip');
  var cards = document.querySelectorAll('.project[data-tags]');
  var status = document.getElementById('filter-status');
  chips.forEach(function (chip) {
    chip.addEventListener('click', function () {
      var f = chip.getAttribute('data-filter');
      var shown = 0;
      chips.forEach(function (c) { c.setAttribute('aria-pressed', String(c === chip)); });
      cards.forEach(function (card) {
        var match = f === 'all' || card.getAttribute('data-tags').split(' ').indexOf(f) !== -1;
        card.hidden = !match;
        if (match) shown++;
      });
      if (status) status.textContent = shown + (shown === 1 ? ' project shown' : ' projects shown');
    });
  });

  /* ---------- Synthetic detection-tuning example ---------- */
  var lab = document.querySelector('[data-lab]');
  if (lab) {
    var thr = document.getElementById('lab-thr');
    var thrOut = document.getElementById('lab-thr-out');
    var succ = document.getElementById('lab-succ');
    var summary = document.getElementById('lab-summary');
    var rows = lab.querySelectorAll('tbody tr');

    var run = function () {
      var n = parseInt(thr.value, 10);
      thrOut.textContent = n;
      var counts = { tp: 0, fp: 0, miss: 0, quiet: 0 };
      rows.forEach(function (row) {
        var seq = row.getAttribute('data-seq');
        var truth = row.getAttribute('data-truth');
        var fails = seq.split('F').length - 1;
        var firstS = seq.indexOf('S');
        var successFollows = firstS !== -1 && seq.indexOf('F') < firstS;
        var alert = fails >= n && (!succ.checked || successFollows);

        var seqCell = row.querySelector('.seq');
        seqCell.textContent = '';
        seq.split('').forEach(function (c) {
          if (c !== 'F' && c !== 'S') return;
          var pill = document.createElement('span');
          pill.className = 'pill ' + c;
          pill.title = c === 'F' ? 'Failed login' : 'Successful login';
          pill.textContent = c;
          seqCell.appendChild(pill);
        });
        row.querySelector('.alert-cell').textContent = alert ? 'Yes' : 'No';

        var key, text;
        if (alert && truth === 'suspicious') { key = 'tp'; text = 'True positive'; }
        else if (alert) { key = 'fp'; text = 'False positive'; }
        else if (truth === 'suspicious') { key = 'miss'; text = 'Missed'; }
        else { key = 'quiet'; text = 'Correctly quiet'; }
        counts[key]++;
        var resCell = row.querySelector('.result-cell');
        resCell.textContent = '';
        var res = document.createElement('span');
        res.className = 'res ' + key;
        res.textContent = text;
        resCell.appendChild(res);
      });
      summary.textContent = 'With N = ' + n + (succ.checked ? ' and a required success' : '') + ': ' +
        counts.tp + ' true positive' + (counts.tp === 1 ? '' : 's') + ', ' +
        counts.fp + ' false positive' + (counts.fp === 1 ? '' : 's') + ', ' +
        counts.miss + ' missed, ' + counts.quiet + ' correctly quiet.';
    };
    thr.addEventListener('input', run);
    succ.addEventListener('change', run);
    run();
  }

  /* ---------- Client-side contact form: opens the visitor's email app ---------- */
  var form = document.getElementById('mail-form');
  if (form) {
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var name = form.elements.name.value.trim();
      var email = form.elements.email.value.trim();
      var message = form.elements.message.value.trim();
      var subject = 'Portfolio enquiry from ' + name;
      var body = message + '\n\n— ' + name + ' (' + email + ')';
      window.location.href = 'mailto:markjoejay1960@gmail.com' +
        '?subject=' + encodeURIComponent(subject) +
        '&body=' + encodeURIComponent(body);
    });
  }
})();
