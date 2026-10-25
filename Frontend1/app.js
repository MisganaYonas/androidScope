    const API_CONFIG = {
      baseUrl: 'http://127.0.0.1:8000',
      uploadPath: '/api/apk/upload',
      startPath: '/api/analysis/start',
      analysisPath: id => `/api/analysis/${encodeURIComponent(id)}`,
      vulnerabilitiesPath: id => `/api/vulnerabilities/${encodeURIComponent(id)}`,
      attackPathsPath: id => `/api/attack-paths/${encodeURIComponent(id)}`,
      pollIntervalMs: 1500,
      maxPollAttempts: 400
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
  if (value === true || value === 1) return 'yes';
  if (value === false || value === 0) return 'no';

  const v = String(value ?? '').trim().toLowerCase();

  if ([
    'true',
    '1',
    'yes',
    'exported',
    'reachable',
    'externally_reachable'
  ].includes(v)) {
    return 'yes';
  }

  if ([
    'false',
    '0',
    'no',
    'not exported',
    'not_exported',
    'unreachable',
    'not reachable',
    'not_reachable'
  ].includes(v)) {
    return 'no';
  }

  return 'unknown';
}

    function renderBackendComponents(rawComponents) {
      const list = document.getElementById('componentList');
      const items = toArray(rawComponents);
      if (!list) return;
      list.replaceChildren();
      items.forEach((raw, index) => {
        const item =
        raw && typeof raw === 'object' && !Array.isArray(raw)
        ? raw
        : {};
        const type = normalizeComponentType(item.type || item.component_type);
        const name = item.name || item.component_name || item.class_name || `Component ${index + 1}`;
        const id = getId(item, ['component_id','id']) || `component-${String(index + 1).padStart(3,'0')}`;
        const reach = normalizeReachability(
        item.exported ??
        item.reachable ??
        item.externally_reachable ??
        item.is_exported
        );
        const card = document.createElement('div'); card.className = 'component'; card.dataset.type = type;
        const icon = document.createElement('div'); icon.className = 'component-icon purple'; icon.textContent = type === 'Activity' ? '▣' : type === 'Service' ? '♙' : type === 'Broadcast Receiver' ? '◉' : '▤';
        const info = document.createElement('div'); info.className = 'component-info';
        const title = document.createElement('strong'); title.textContent = name;
        const sub = document.createElement('small'); sub.textContent = type;
        
info.append(title, sub);

const intentFilters = Array.isArray(item.intent_filters)
  ? item.intent_filters
  : item.intent_filters && typeof item.intent_filters === 'object'
    ? Object.values(item.intent_filters).flat()
    : [];

if (intentFilters.length > 0) {
  const filterInfo = document.createElement('small');
  filterInfo.className = 'component-intent-filters';
  filterInfo.textContent =
    'Intent filters: ' +
    intentFilters
      .map(filter =>
        typeof filter === 'string'
          ? filter
          : filter?.action || filter?.name || JSON.stringify(filter)
      )
      .join(', ');

  info.appendChild(filterInfo);
}

        const right = document.createElement('div'); right.className = 'component-right';
        const badge = document.createElement('span'); badge.className = `badge ${reach === 'yes' ? 'exported' : reach === 'no' ? 'not-exported' : ''}`;
        badge.textContent = reach === 'yes' ? 'Exported' : reach === 'no' ? 'Not Exported' : 'Reachability Unknown';
        const idEl = document.createElement('div'); idEl.className = 'component-id'; idEl.textContent = id;
        right.append(badge, idEl); card.append(icon, info, right); list.append(card);
      });
      const counts = items.reduce((acc, item) => { const type = normalizeComponentType(item.type || item.component_type); acc[type] = (acc[type] || 0) + 1; return acc; }, {});
      document.getElementById('totalComponentsStat').textContent = String(items.length);
      
document.getElementById('reachableStat').textContent = String(
  items.filter(item =>
    item &&
    typeof item === 'object' &&
    normalizeReachability(
      item.exported ??
      item.reachable ??
      item.externally_reachable ??
      item.is_exported
    ) === 'yes'
  ).length
);

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
    let backendAttackPaths = [];



function renderBackendPaths(rawPaths) {
  if (rawPaths && !Array.isArray(rawPaths)) {
    rawPaths = rawPaths.attack_paths || rawPaths.paths || [];
  }

  backendAttackPaths = toArray(rawPaths);

  const mode =
    document.getElementById('pathSelect')?.value || 'complete';

  const paths = backendAttackPaths.filter(path => {
    const rawNodes = toArray(
      path.nodes || path.steps || path.path
    );

    if (mode !== 'static') return true;

    return !rawNodes.some(node => {
      const type = String(
        typeof node === 'object' && node !== null ? node.type || '' : ''
      ).toLowerCase();

      const detail = String(
        typeof node === 'object' && node !== null
          ? node.detail || node.description || ''
          : node || ''
      ).toLowerCase();

      return type.includes('runtime') ||
        detail.includes('runtime observation');
    });
  });

paths.sort((a, b) => {
  const statusA = String(a.status || '').toUpperCase();
  const statusB = String(b.status || '').toUpperCase();

  if (statusA === 'CORRELATED' && statusB !== 'CORRELATED') return -1;
  if (statusB === 'CORRELATED' && statusA !== 'CORRELATED') return 1;

  return 0;
});

  document.getElementById('attackPathsStat').textContent =
    String(paths.length);

  if (!paths.length) {
    renderAttackGraph([]);
    document.getElementById('graphCaption').textContent =
      'The backend returned no attack paths for this analysis.';
    return;
  }

  const graphNodes = [];

  paths.forEach((path, pathIndex) => {
    const rawNodes = toArray(
      path.nodes || path.steps || path.path
    );

    if (pathIndex > 0) {
      graphNodes.push({
        label: `Attack Path ${pathIndex + 1}`,
        detail: 'Separate backend attack path',
        kind: 'operation',
        reachability: 'Reachability: unknown'
      });
    }

    rawNodes.forEach((node, index) => {
      if (typeof node === 'string') {
        graphNodes.push({
          label: node,
          detail: '',
          kind: index === 0 ? 'external' : 'operation',
          reachability: 'Reachability: unknown'
        });
        return;
      }

      const safeNode =
        node && typeof node === 'object' ? node : {};

      const reach = normalizeReachability(
        safeNode.exported ??
        safeNode.reachable ??
        safeNode.reachability
      );

      const evidenceIds = toArray(safeNode.evidence_ids);
     const evidenceCount = Number(
     safeNode.evidence_count ?? evidenceIds.length
     );
      graphNodes.push({
        label:
          safeNode.step ||
          safeNode.component_name ||
          safeNode.name ||
          safeNode.label ||
          safeNode.method ||
          safeNode.type ||
          `Step ${index + 1}`,

        component_name: safeNode.component_name,

        detail:
          safeNode.detail ||
          safeNode.description ||
          safeNode.method_id ||
          safeNode.component_id ||
          '',

        kind: String(safeNode.type || '').toLowerCase().includes('runtime')
          ? 'runtime'
          : (index === 0 ? 'external' : 'operation'),

        reachability:
          reach === 'unknown'
            ? 'Reachability: unknown'
            : reach === 'yes'
              ? 'Externally reachable'
              : 'Not externally reachable',

        evidence_ids: evidenceIds,
        evidence_count: evidenceCount
      });
    });
  });

  renderAttackGraph(graphNodes);

  const statuses = paths.map(path =>
    String(path.status || 'UNKNOWN').toUpperCase()
  );

  document.getElementById('graphCaption').textContent =
    `${paths.length} attack path(s) returned by the backend. ` +
    `Path statuses: ${statuses.join(', ')}. ` +
    'Unknown reachability remains unknown. ' +
    'Arrows between separate paths do not prove a continuous attack chain.';
}

function renderBackendFindings(rawFindings) {
  const findings = toArray(rawFindings);

  document.getElementById('findingsStat').textContent =
    String(findings.length);

  document.getElementById('findingsSubStat').textContent =
    findings.length
      ? 'Candidate findings · backend results'
      : 'No findings returned';

  const container =
    document.getElementById('findingsList') ||
    document.getElementById('findingsContainer');

  if (!container) {
    console.warn(
      'Findings display container not found in HTML.'
    );
    return;
  }

  container.replaceChildren();

  if (findings.length === 0) {
    const empty = document.createElement('p');
    empty.textContent = 'No candidate findings returned by the backend.';
    container.appendChild(empty);
    return;
  }

  findings.forEach((finding, index) => {
    const item =
      finding && typeof finding === 'object' ? finding : {};

    const card = document.createElement('article');
    card.className = 'finding-card';

    const title = document.createElement('h3');
    title.textContent =
      item.title ||
      item.name ||
      item.rule_name ||
      item.type ||
      `Candidate finding ${index + 1}`;

    const status = document.createElement('p');
    status.textContent =
      `Status: ${item.status || 'Unknown'}`;

    const description = document.createElement('p');
    description.textContent =
      item.description ||
      item.detail ||
      item.message ||
      'No description provided by the backend.';

    card.append(title, status, description);

    const evidenceIds = Array.isArray(item.evidence_ids)
      ? item.evidence_ids
      : [];

    if (evidenceIds.length > 0) {
      const evidence = document.createElement('p');
      evidence.textContent =
        `Evidence IDs: ${evidenceIds.join(', ')}`;
      card.appendChild(evidence);
    }

    container.appendChild(card);
  });
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
  graph.textContent =
    'No correlated attack path is available. Unknown reachability must not be treated as reachable.';
  return;
}

nodes.forEach((node, index) => {
  const step = document.createElement('div');
  step.className = 'graph-step';

  const card = document.createElement('div');
  const reach = String(
    node.reachability || 'Reachability: unknown'
  ).toLowerCase();

  const isRuntime =
    node.kind === 'runtime' ||
    String(node.type || '').toLowerCase().includes('runtime');

  card.className =
    `graph-node ${node.kind || ''} ` +
    `${isRuntime ? 'runtime-node' : ''} ` +
    `${reach.includes('unknown') ? 'unknown' : ''}`;

  const number = document.createElement('span');
  number.className = 'step-number';
  number.textContent = `STEP ${index + 1}`;

  const icon = document.createElement('span');
  icon.className = 'graph-icon';
  icon.textContent = node.icon || '•';

  const title = document.createElement('strong');
  title.textContent =
    node.step ||
    node.component_name ||
    node.label ||
    node.name ||
    node.method ||
    'Unnamed step';

  const detail = document.createElement('small');
  detail.textContent =
    node.detail ||
    node.description ||
    node.component_id ||
    '';

  const badge = document.createElement('span');
  badge.className = 'reachability';
  badge.textContent =
    node.reachability || 'Reachability: unknown';

  card.append(number, icon, title, detail, badge);

  const evidenceIds = Array.isArray(node.evidence_ids)
    ? node.evidence_ids
    : [];

  const evidenceCount = Number(
  node.evidence_count ?? evidenceIds.length
);

  const evidence = document.createElement('small');
  evidence.className = 'evidence-info';

  if (isRuntime) {
    evidence.textContent =
      evidenceCount > 0
        ? `Runtime evidence records: ${evidenceCount}`
        : 'Not observed yet';
  } else if (evidenceCount > 0) {
    evidence.textContent =
      `Evidence records: ${evidenceCount}` +
      (evidenceIds.length
        ? ` · IDs: ${evidenceIds.join(', ')}`
        : '');
  } else {
    evidence.textContent = 'No evidence records provided';
  }

  card.append(evidence);
  step.append(card);
  graph.append(step);

  
if (index < nodes.length - 1) {
  const currentNode = nodes[index];
  const nextNode = nodes[index + 1];

  const isCurrentSeparator =
  String(currentNode.label || '').startsWith('Attack Path ');

const isNextSeparator =
  String(nextNode.label || '').startsWith('Attack Path ');

if (!isCurrentSeparator && !isNextSeparator) {
    const link = document.createElement('div');
    link.className =
      `graph-link ${
        nextNode.kind === 'runtime' ? 'runtime-arrow' : ''
      }`;
    link.setAttribute('aria-hidden', 'true');
    link.textContent = '➜';
    graph.append(link);
  }
}

});
}
    renderAttackGraph([]);

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
  const pathSelect = document.getElementById('pathSelect');

  if (pathSelect) {
    pathSelect.value = event.target.value;
  }

  updateAttackPath();
});

    document.getElementById('pathSelect').addEventListener('change', event => {
  const settingsPathSelect = document.getElementById('settingsPathSelect');

  if (settingsPathSelect) {
    settingsPathSelect.value = event.target.value;
  }

  updateAttackPath();
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
      uploadStatus.textContent =
  `${file.name} selected · ${(file.size / (1024 * 1024)).toFixed(2)} MB. Ready to upload to the backend.`;
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
        const applicationId = getId(uploaded, ['application_id']);
        if (!applicationId) {
        throw new Error('The upload response did not include application_id.');
        }
        uploadStatus.textContent = 'APK uploaded. Starting analysis…';
        const startBody = { application_id: applicationId };
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
       
const finalStatus = String(
  analysis?.status || analysis?.state || ''
).toLowerCase();

if (['failed', 'error', 'cancelled'].includes(finalStatus)) {
  const backendErrors = analysis?.errors;

  const errorDetails = backendErrors
    ? (typeof backendErrors === 'string'
        ? backendErrors
        : JSON.stringify(backendErrors, null, 2))
    : '';

  const errorMessage =
    analysis?.message ||
    analysis?.error ||
    `Analysis ended with status: ${finalStatus}`;

  throw new Error(
    errorDetails
      ? `${errorMessage}\nBackend stage errors:\n${errorDetails}`
      : errorMessage
  );
}

if (!['completed', 'complete', 'done', 'success', 'succeeded'].includes(finalStatus)) {
  throw new Error(
    'Analysis is still running. Try again later or increase maxPollAttempts in API_CONFIG.'
  );
}

const [componentsResult, pathsResult, findingsResult] =
  await Promise.allSettled([
    apiRequest(`/api/components/${encodeURIComponent(analysisId)}`),
    apiRequest(API_CONFIG.attackPathsPath(analysisId)),
    apiRequest(API_CONFIG.vulnerabilitiesPath(analysisId))
  ]);

const componentResults =
  componentsResult.status === 'fulfilled'
    ? (
        componentsResult.value.components ??
        componentsResult.value
      )
    : [];

if (componentsResult.status === 'fulfilled') {
  renderBackendComponents(
    Array.isArray(componentResults)
      ? componentResults
      : []
  );
} else {
  console.error('Could not load components:', componentsResult.reason);
}

const paths =
  pathsResult.status === 'fulfilled'
    ? (
        pathsResult.value.attack_paths ??
        pathsResult.value.paths ??
        pathsResult.value
      )
    : [];

const findings =
  findingsResult.status === 'fulfilled'
    ? (
        findingsResult.value.findings ??
        findingsResult.value.vulnerabilities ??
        findingsResult.value
      )
    : [];

        
        renderBackendPaths(Array.isArray(paths) ? paths : []);
        renderBackendFindings(Array.isArray(findings) ? findings : []);
        window.droidTraceBackendResultsLoaded = true;

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

    const staticPathNodes = demoPathNodes.filter(node => node.kind !== 'runtime');
    const pathSelect = document.getElementById('pathSelect');
    
    function updateAttackPath() {
  if (window.droidTraceBackendResultsLoaded) {
    renderBackendPaths(backendAttackPaths);
    return;
  }

  const isStaticOnly = pathSelect.value === 'static';

  renderAttackGraph(
    isStaticOnly ? staticPathNodes : demoPathNodes
  );

  const caption = document.getElementById('graphCaption');

  caption.innerHTML = isStaticOnly
    ? '<strong>Static Only:</strong> shows illustrative static steps, not verified APK findings.'
    : '<strong>Complete Path:</strong> shows illustrative sample steps, not captured from a real device.';
    }

    pathSelect.addEventListener('change', updateAttackPath);
    updateAttackPath();
