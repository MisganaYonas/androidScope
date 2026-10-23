    const API_CONFIG = {
      baseUrl: 'http://127.0.0.1:8000',
      uploadPath: '/api/apk/upload',
      startPath: '/api/analysis/start',
      analysisPath: id => `/api/analysis/${encodeURIComponent(id)}`,
      vulnerabilitiesPath: id => `/api/vulnerabilities/${encodeURIComponent(id)}`,
      attackPathsPath: id => `/api/attack-paths/${encodeURIComponent(id)}`,
      pollIntervalMs: 1500,
      maxPollAttempts: 120
    };

    function unwrapApi(value) {
      let current = value;
      for (let i = 0; i < 3; i++) {
        if (current && typeof current === 'object' && !Array.isArray(current) && current.data && typeof current.data === 'object') current = current.data;
        else break;
      }
      return current;
    }
    async function apiRequest(path, options = {}) {
      const response = await fetch(`${API_CONFIG.baseUrl}${path}`, options);
      const raw = await response.text();
      let body = {};
      if (raw) { try { body = JSON.parse(raw); } catch { body = { message: raw }; } }
      if (!response.ok) {
        const message = body.detail || body.message || body.error || `HTTP ${response.status}`;
        throw new Error(`${message}`);
      }
      return unwrapApi(body);
    }
    function getId(obj, keys) {
      for (const key of keys) if (obj && obj[key] !== undefined && obj[key] !== null && obj[key] !== '') return obj[key];
      return null;
    }
    function toArray(value) { return Array.isArray(value) ? value : (value && Array.isArray(value.results) ? value.results : (value && Array.isArray(value.items) ? value.items : [])); }
    function normalizeComponentType(type) {
      const t = String(type || 'component').toLowerCase().replace(/[_-]/g, ' ');
      if (t.includes('activity')) return 'Activity';
      if (t.includes('service')) return 'Service';
      if (t.includes('receiver')) return 'Broadcast Receiver';
      if (t.includes('provider')) return 'Provider';
      return 'Component';
    }
    function normalizeReachability(value) {
      if (value === true) return 'yes';
      if (value === false) return 'no';
      const v = String(value ?? '').toLowerCase();
      if (['true','yes','exported','reachable','externally_reachable'].includes(v)) return 'yes';
      if (['false','no','not exported','not_exported','unreachable'].includes(v)) return 'no';
      return 'unknown';
    }
    function renderBackendComponents(rawComponents) {
      const list = document.getElementById('componentList');
      const items = toArray(rawComponents);
      if (!items.length) return;
      list.replaceChildren();
      items.forEach((raw, index) => {
        const item = raw || {};
        const type = normalizeComponentType(item.type || item.component_type);
        const name = item.name || item.component_name || item.class_name || `Component ${index + 1}`;
        const id = getId(item, ['component_id','id']) || `component-${String(index + 1).padStart(3,'0')}`;
        const reach = normalizeReachability(item.exported ?? item.reachable ?? item.externally_reachable);
        const card = document.createElement('div'); card.className = 'component'; card.dataset.type = type;
        const icon = document.createElement('div'); icon.className = 'component-icon purple'; icon.textContent = type === 'Activity' ? '▣' : type === 'Service' ? '♙' : type === 'Broadcast Receiver' ? '◉' : '▤';
        const info = document.createElement('div'); info.className = 'component-info';
        const title = document.createElement('strong'); title.textContent = name;
        const sub = document.createElement('small'); sub.textContent = type;
        info.append(title, sub);
        const right = document.createElement('div'); right.className = 'component-right';
        const badge = document.createElement('span'); badge.className = `badge ${reach === 'yes' ? 'exported' : reach === 'no' ? 'not-exported' : ''}`;
        badge.textContent = reach === 'yes' ? 'Exported' : reach === 'no' ? 'Not Exported' : 'Reachability Unknown';
        const idEl = document.createElement('div'); idEl.className = 'component-id'; idEl.textContent = id;
        right.append(badge, idEl); card.append(icon, info, right); list.append(card);
      });
      const counts = items.reduce((acc, item) => { const type = normalizeComponentType(item.type || item.component_type); acc[type] = (acc[type] || 0) + 1; return acc; }, {});
      document.getElementById('totalComponentsStat').textContent = String(items.length);
      document.getElementById('reachableStat').textContent = String(items.filter(item => normalizeReachability(item.exported ?? item.reachable ?? item.externally_reachable) === 'yes').length);
      document.getElementById('componentBreakdownStat').textContent = `Activities: ${counts.Activity || 0} · Receivers: ${counts['Broadcast Receiver'] || 0} · Services: ${counts.Service || 0} · Providers: ${counts.Provider || 0}`;
      document.querySelectorAll('.filter').forEach(button => {
        const filter = button.dataset.filter;
        const count = filter === 'All' ? items.length : items.filter(item => normalizeComponentType(item.type || item.component_type) === filter).length;
        const label = filter === 'Activity' ? 'Activities' : filter === 'Service' ? 'Services' : filter === 'Broadcast Receiver' ? 'Receivers' : filter === 'Provider' ? 'Providers' : 'All';
        button.textContent = `${label} (${count})`;
      });
      // Refresh component references because backend results replace the original demo list.
      components = [...document.querySelectorAll('.component')];
      updateComponents();
    }
    function renderBackendPaths(rawPaths) {
      const paths = toArray(rawPaths);
      document.getElementById('attackPathsStat').textContent = String(paths.length);
      if (!paths.length) {
        renderAttackGraph([]);
        document.getElementById('graphCaption').textContent = 'The backend returned no attack paths for this analysis.';
        return;
      }
      const path = paths[0] || {};
      const rawNodes = toArray(path.nodes || path.steps || path.path);
      const nodes = rawNodes.map((node, index) => {
        if (typeof node === 'string') return { label: node, detail: '', kind: index === 0 ? 'external' : 'operation', reachability: 'unknown' };
        const reach = normalizeReachability(node.exported ?? node.reachable ?? node.reachability);
        return { label: node.component_name || node.name || node.label || node.method || node.type || `Step ${index + 1}`, component_name: node.component_name, detail: node.detail || node.description || node.method_id || node.component_id || '', kind: String(node.type || '').toLowerCase().includes('runtime') ? 'runtime' : (index === 0 ? 'external' : 'operation'), reachability: reach === 'unknown' ? 'Reachability: unknown' : reach === 'yes' ? 'Externally reachable' : 'Not externally reachable' };
      });
      renderAttackGraph(nodes);
      const status = String(path.status || 'UNKNOWN').toUpperCase();
      document.getElementById('graphCaption').textContent = `Backend attack path status: ${status}. A path is correlated only when static and runtime evidence are connected by the analysis engine.`;
    }
    function renderBackendFindings(rawFindings) {
      const findings = toArray(rawFindings);
      document.getElementById('findingsStat').textContent = String(findings.length);
      const severities = findings.map(f => String(f.severity || '').toLowerCase());
      document.getElementById('findingsSubStat').textContent = findings.length ? `${severities.filter(s => s === 'high' || s === 'critical').length} high/critical · backend results` : 'No findings returned';
    }

    // Interactive illustrative attack-path graph. Sample data is used until a real API analysis succeeds.
    const demoPathNodes = [
      { label: 'External input', detail: 'Intent from another app', icon: '↗', kind: 'external', reachability: 'Entry point (demo)' },
      { label: 'MainActivity', detail: 'component-001 · manifest export status is demo-only', icon: '▣', kind: 'component', reachability: 'Exported (demo)' },
      { label: 'Intent extra: url', detail: 'Data received from the Intent', icon: '⇢', kind: 'data', reachability: 'Data flow' },
      { label: 'WebView.loadUrl()', detail: 'Sensitive navigation operation', icon: '</>', kind: 'operation', reachability: 'Review input validation' },
      { label: 'Runtime observation', detail: 'Example event only; not device-captured', icon: '◉', kind: 'runtime', reachability: 'Demo evidence' }
    ];
    function renderAttackGraph(nodes = demoPathNodes) {
      const graph = document.getElementById('attackGraph');
      graph.replaceChildren();
      if (!Array.isArray(nodes) || nodes.length === 0) {
        graph.innerHTML = '<div class="path-empty">No correlated attack path is available. Missing or unknown manifest reachability must not be treated as reachable.</div>';
        return;
      }
      nodes.forEach((node, index) => {
        const step = document.createElement('div'); step.className = 'graph-step';
        const card = document.createElement('div');
        const reach = String(node.reachability || 'unknown').toLowerCase();
        card.className = `graph-node ${node.kind || ''} ${node.kind === 'runtime' ? 'runtime-node' : ''} ${reach.includes('unknown') ? 'unknown' : ''}`;
        const number = document.createElement('span'); number.className = 'step-number'; number.textContent = `STEP ${index + 1}`;
        const icon = document.createElement('span'); icon.className = 'graph-icon'; icon.textContent = node.icon || '•';
        const title = document.createElement('strong'); title.textContent = node.component_name || node.label || node.name || 'Unnamed step';
        const detail = document.createElement('small'); detail.textContent = node.detail || node.description || node.component_id || '';
        const badge = document.createElement('span'); badge.className = 'reachability'; badge.textContent = node.reachability || 'Reachability: unknown';
        card.append(number, icon, title, detail, badge); step.append(card); graph.append(step);
        if (index < nodes.length - 1) { const link = document.createElement('div'); link.className = `graph-link ${nodes[index + 1] && nodes[index + 1].kind === 'runtime' ? 'runtime-arrow' : ''}`; link.setAttribute('aria-hidden','true'); link.textContent = '➜'; graph.append(link); }
      });
    }
    renderAttackGraph();

    // Settings popup and working display controls.
    const settingsModal = document.getElementById('settingsModal');
    const settingsClose = document.getElementById('settingsClose');
    const settingsNav = [...document.querySelectorAll('.nav a')].find(link => link.getAttribute('href') === '#settings');
    settingsNav?.addEventListener('click', event => { event.preventDefault(); settingsModal.classList.add('open'); });
    settingsClose.addEventListener('click', () => settingsModal.classList.remove('open'));
    settingsModal.addEventListener('click', event => { if (event.target === settingsModal) settingsModal.classList.remove('open'); });
    document.addEventListener('keydown', event => { if (event.key === 'Escape') settingsModal.classList.remove('open'); });
    document.getElementById('showComponentIds').addEventListener('change', event => {
      document.querySelectorAll('.component-id').forEach(el => el.hidden = !event.target.checked);
    });
    document.getElementById('showExportStatus').addEventListener('change', event => {
      document.querySelectorAll('.component-right .badge').forEach(el => el.hidden = !event.target.checked);
    });
    document.getElementById('settingsPathSelect').addEventListener('change', event => {
      const nodes = event.target.value === 'static' ? demoPathNodes.filter(node => node.kind !== 'runtime') : demoPathNodes;
      renderAttackGraph(nodes);
      const pathSelect = document.getElementById('pathSelect');
      if (pathSelect) pathSelect.value = event.target.value;
    });
    document.getElementById('pathSelect').addEventListener('change', event => {
      const nodes = event.target.value === 'static' ? demoPathNodes.filter(node => node.kind !== 'runtime') : demoPathNodes;
      renderAttackGraph(nodes);
      document.getElementById('settingsPathSelect').value = event.target.value;
    });
    document.getElementById('settingsEvidenceSelect').addEventListener('change', event => {
      document.querySelector(`.tab[data-tab="${event.target.value}"]`)?.click();
    });


    // File picker validation. Actual upload needs the backend's agreed request body/endpoint.
    const apkFileInput = document.getElementById('apkFile');
    const analyzeButton = document.getElementById('analyzeButton');
    const uploadStatus = document.getElementById('uploadStatus');
    apkFileInput.addEventListener('change', () => {
      const file = apkFileInput.files && apkFileInput.files[0];
      uploadStatus.className = 'upload-status';
      if (!file) { uploadStatus.textContent = 'Choose an .apk file to begin.'; return; }
      if (!file.name.toLowerCase().endsWith('.apk')) {
        apkFileInput.value = '';
        uploadStatus.className = 'upload-status error';
        uploadStatus.textContent = 'Unsupported file type. Please select an Android .apk file.';
        return;
      }
      uploadStatus.textContent = `${file.name} selected · ${(file.size / (1024 * 1024)).toFixed(2)} MB. Backend upload is not connected yet.`;
    });
    analyzeButton.addEventListener('click', async () => {
      const file = apkFileInput.files && apkFileInput.files[0];
      uploadStatus.className = 'upload-status';
      if (!file) {
        uploadStatus.className = 'upload-status error';
        uploadStatus.textContent = 'Please choose an APK file first.';
        apkFileInput.focus(); return;
      }
      if (!file.name.toLowerCase().endsWith('.apk')) {
        uploadStatus.className = 'upload-status error';
        uploadStatus.textContent = 'Please select a valid .apk file.'; return;
      }
      analyzeButton.disabled = true;
      uploadStatus.className = 'upload-status loading';
      uploadStatus.textContent = 'Uploading APK to the backend…';
      try {
        const form = new FormData();
        form.append('file', file);
        const uploaded = await apiRequest(API_CONFIG.uploadPath, { method: 'POST', body: form });
        const apkId = getId(uploaded, ['apk_id','application_id','id','upload_id']);
        uploadStatus.textContent = 'APK uploaded. Starting analysis…';
        const startBody = apkId ? { apk_id: apkId } : { filename: file.name };
        const started = await apiRequest(API_CONFIG.startPath, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(startBody) });
        const analysisId = getId(started, ['analysis_id','id','task_id','job_id']) || getId(uploaded, ['analysis_id']);
        if (!analysisId) throw new Error('The backend response did not include an analysis ID. Ask the backend teammate to return analysis_id or id from POST /api/analysis/start.');
        uploadStatus.textContent = `Analysis started (${analysisId}). Waiting for results…`;
        let analysis = null;
        for (let attempt = 0; attempt < API_CONFIG.maxPollAttempts; attempt++) {
          analysis = await apiRequest(API_CONFIG.analysisPath(analysisId));
          const status = String(analysis.status || analysis.state || '').toLowerCase();
          if (['completed','complete','done','success','succeeded','failed','error','cancelled'].includes(status)) break;
          await new Promise(resolve => setTimeout(resolve, API_CONFIG.pollIntervalMs));
        }
        const finalStatus = String(analysis?.status || analysis?.state || '').toLowerCase();
        if (['failed','error','cancelled'].includes(finalStatus)) throw new Error(analysis.message || analysis.error || `Analysis ended with status: ${finalStatus}`);
        if (!['completed','complete','done','success','succeeded'].includes(finalStatus)) throw new Error('Analysis is still running. Try again later or increase maxPollAttempts in API_CONFIG.');
        const [pathsResult, findingsResult] = await Promise.allSettled([
          apiRequest(API_CONFIG.attackPathsPath(analysisId)),
          apiRequest(API_CONFIG.vulnerabilitiesPath(analysisId))
        ]);
        const componentResults = analysis.components || analysis.component_results || analysis.manifest_results?.components || analysis.results?.components;
        if (componentResults) renderBackendComponents(componentResults);
        const paths = pathsResult.status === 'fulfilled' ? (pathsResult.value.attack_paths || pathsResult.value.paths || pathsResult.value) : (analysis.attack_paths || analysis.paths || []);
        const findings = findingsResult.status === 'fulfilled' ? (findingsResult.value.findings || findingsResult.value.vulnerabilities || findingsResult.value) : (analysis.findings || analysis.vulnerabilities || []);
        renderBackendPaths(paths);
        renderBackendFindings(findings);
        uploadStatus.className = 'upload-status success';
        uploadStatus.textContent = `Analysis completed for ${file.name}. Results loaded from the backend${pathsResult.status === 'rejected' || findingsResult.status === 'rejected' ? ' (some optional result endpoints were unavailable)' : ''}.`;
      } catch (error) {
        uploadStatus.className = 'upload-status error';
        uploadStatus.textContent = `Backend integration error: ${error.message}. Check API_CONFIG, the backend endpoint contract, and CORS settings.`;
      } finally { analyzeButton.disabled = false; }
    });

    // Search and filter the demo component list.
    const searchInput = document.getElementById('componentSearch');
    let components = [...document.querySelectorAll('.component')];
    const filters = [...document.querySelectorAll('.filter')];
    let activeFilter = 'All';

    function updateComponents() {
      const query = searchInput.value.trim().toLowerCase();
      let visibleCount = 0;
      components.forEach(item => {
        const matchesText = item.textContent.toLowerCase().includes(query);
        const matchesType = activeFilter === 'All' || item.dataset.type === activeFilter;
        item.hidden = !(matchesText && matchesType);
        if (!item.hidden) visibleCount++;
      });
      let emptyMessage = document.getElementById('componentNoResults');
      if (!emptyMessage) {
        emptyMessage = document.createElement('p');
        emptyMessage.id = 'componentNoResults';
        emptyMessage.className = 'path-empty';
        emptyMessage.textContent = 'No components match your search. Try another name or filter.';
        document.getElementById('componentList').after(emptyMessage);
      }
      emptyMessage.hidden = visibleCount !== 0;
    }
    const suggestions = document.getElementById('searchSuggestions');
    const modal = document.getElementById('componentModal');
    const modalTitle = document.getElementById('componentModalTitle');
    const modalList = document.getElementById('componentModalList');

    function openComponentPopup(title, items) {
      modalTitle.textContent = title;
      modalList.replaceChildren();
      if (!items.length) {
        const empty = document.createElement('p');
        empty.className = 'path-empty';
        empty.textContent = 'No matching components found. Try another search.';
        modalList.append(empty);
      } else {
        items.forEach(item => {
          const clone = item.cloneNode(true);
          clone.hidden = false;
          modalList.append(clone);
        });
      }
      modal.classList.add('open');
    }

    function updateSuggestions() {
      const query = searchInput.value.trim().toLowerCase();
      suggestions.replaceChildren();
      if (!query) { suggestions.classList.remove('open'); return; }
      const matches = components.filter(item => item.textContent.toLowerCase().includes(query));
      matches.slice(0, 6).forEach(item => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.textContent = item.querySelector('.component-info strong')?.textContent || item.textContent.trim();
        btn.addEventListener('click', () => {
          searchInput.value = btn.textContent;
          suggestions.classList.remove('open');
          updateComponents();
          openComponentPopup('Search result: ' + btn.textContent, components.filter(c => c.textContent.toLowerCase().includes(btn.textContent.toLowerCase())));
        });
        suggestions.append(btn);
      });
      if (!matches.length) {
        const noMatch = document.createElement('button');
        noMatch.type = 'button'; noMatch.textContent = 'No matching components'; noMatch.disabled = true;
        suggestions.append(noMatch);
      }
      suggestions.classList.add('open');
    }

    searchInput.addEventListener('input', () => { updateComponents(); updateSuggestions(); });
    searchInput.addEventListener('focus', updateSuggestions);
    filters.forEach(button => button.addEventListener('click', () => {
      activeFilter = button.dataset.filter;
      filters.forEach(item => item.classList.toggle('active', item === button));
      updateComponents();
      const filtered = components.filter(item => activeFilter === 'All' || item.dataset.type === activeFilter);
      const label = button.textContent.replace(/\s*\(\d+\)/, '').trim();
      openComponentPopup(label, filtered.filter(item => item.textContent.toLowerCase().includes(searchInput.value.trim().toLowerCase())));
    }));
    document.getElementById('componentModalClose').addEventListener('click', () => modal.classList.remove('open'));
    modal.addEventListener('click', event => { if (event.target === modal) modal.classList.remove('open'); });
    document.addEventListener('keydown', event => { if (event.key === 'Escape') { modal.classList.remove('open'); suggestions.classList.remove('open'); } });
    document.addEventListener('click', event => { if (!event.target.closest('.search-wrap')) suggestions.classList.remove('open'); });

    // Switch between static and runtime evidence examples.
    const evidenceContent = document.getElementById('evidenceContent');
    const originalStaticEvidence = evidenceContent.innerHTML;
    document.querySelectorAll('.tab').forEach(button => button.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(tab => tab.classList.toggle('active', tab === button));
      if (button.dataset.tab === 'static') {
        evidenceContent.innerHTML = originalStaticEvidence;
      } else {
        evidenceContent.innerHTML = `
          <div class="evidence-title">◈ Runtime Observation</div>
          <div class="evidence-sub">Illustrative event — not captured from a real device</div>
          <pre><code>[DEMO] Activity launched: MainActivity
[DEMO] Intent extra found: url
[DEMO] WebView navigation requested
[DEMO] Event linked to component-001</code></pre>
          <div class="details"><h4>Runtime Event Details</h4>
            <div class="detail-row"><span>Event</span><span>WebView navigation</span></div>
            <div class="detail-row"><span>Component</span><span>MainActivity</span></div>
            <div class="detail-row"><span>Source</span><span>Demo event stream</span></div>
            <div class="detail-row"><span>Verification</span><span>Not verified</span></div>
          </div>`;
      }
    }));

    // Complete Path includes the illustrative runtime observation; Static Only excludes it.
    // Both are demo examples, not results from an uploaded APK.
    const staticPathNodes = demoPathNodes.filter(node => node.kind !== 'runtime');
    const pathSelect = document.getElementById('pathSelect');
    function updateAttackPath() {
      const isStaticOnly = pathSelect.value === 'static';
      renderAttackGraph(isStaticOnly ? staticPathNodes : demoPathNodes);
      const caption = document.getElementById('graphCaption');
      caption.innerHTML = isStaticOnly
        ? '<strong>Static Only:</strong> shows the example static data-flow steps. Runtime observation is excluded. These are illustrative sample steps, not verified APK findings.'
        : '<strong>Complete Path:</strong> shows the example data flow plus a runtime-observation step. The runtime step is illustrative only and was not captured from a real device.';
    }
    pathSelect.addEventListener('change', updateAttackPath);
    updateAttackPath();
