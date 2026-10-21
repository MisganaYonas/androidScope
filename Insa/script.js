const demoData = window.demoData || {};

function setText(id, value) {
  const element = document.getElementById(id);
  if (element) element.textContent = value ?? "";
}

function renderSummary(data) {
  if (!data || !data.application) return;

  setText("apkName", data.application.name);
  setText("packageName", `Package: ${data.application.packageName}`);
  setText("analysisId", data.application.analysisId);
  setText("activitiesCount", data.componentCounts.activities);
  setText("servicesCount", data.componentCounts.services);
  setText("receiversCount", data.componentCounts.receivers);
  setText("providersCount", data.componentCounts.providers);
  setText("attackPathCount", data.attackPaths.length);
  setText("componentTotal", `${data.components.length} example components`);
  setText("componentFootnote", `Showing ${data.components.length} example components`);

  const staticCount = data.evidence.filter(item => item.type === "Static analysis").length;
  const runtimeCount = data.evidence.filter(item => item.type === "Runtime observation").length;
  setText("staticEvidenceCount", staticCount);
  setText("runtimeEvidenceCount", runtimeCount);

  const path = data.attackPaths[0];
  const status = path ? path.status : "NO PATHS";
  setText("correlationStatus", status.replaceAll("_", " "));
  setText("pathStatus", status.replaceAll("_", " "));

  const statusBadge = document.getElementById("pathStatus");
  if (statusBadge) statusBadge.className = `status-badge ${status.toLowerCase()}`;

  setText("pathExplanation", path ? path.explanation : "No path is available in this demo.");
  const progress = document.getElementById("pathProgress");
  if (progress) progress.style.width = data.attackPaths.length ? "45%" : "0%";
}

function renderComponents(components) {
  const list = document.getElementById("componentList");
  if (!list) return;
  list.replaceChildren();

  components.forEach(component => {
    const row = document.createElement("tr");
    const name = document.createElement("td");
    name.textContent = component.name;

    const typeCell = document.createElement("td");
    const type = document.createElement("span");
    type.className = "type-pill";
    type.textContent = component.type;
    typeCell.append(type);

    const exportedCell = document.createElement("td");
    const exported = document.createElement("span");
    exported.className = component.exported ? "export-pill" : "export-pill no";
    exported.textContent = component.exported ? "YES" : "NO";
    exportedCell.append(exported);

    row.append(name, typeCell, exportedCell);
    list.append(row);
  });
}

function renderAttackPath(path) {
  const container = document.getElementById("attackPathNodes");
  if (!container) return;
  container.replaceChildren();

  if (!path) {
    container.textContent = "No attack path is available in this demo.";
    return;
  }

  path.nodes.forEach((node, index) => {
    const step = document.createElement("div");
    step.className = "flow-step";

    const card = document.createElement("div");
    card.className = node.runtime ? "flow-node runtime-node" : "flow-node";

    const icon = document.createElement("span");
    icon.className = "node-icon";
    icon.textContent = node.icon;

    const title = document.createElement("strong");
    title.textContent = node.label;

    const detail = document.createElement("small");
    detail.textContent = node.detail;

    card.append(icon, title, detail);
    step.append(card);
    container.append(step);

    if (index < path.nodes.length - 1) {
      const arrow = document.createElement("div");
      arrow.className = "flow-arrow";
      arrow.textContent = "→";
      arrow.setAttribute("aria-hidden", "true");
      container.append(arrow);
    }
  });
}

function showEvidence(id) {
  const item = demoData.evidence.find(entry => entry.id === id);
  if (!item) return;

  document.querySelectorAll(".evidence-item").forEach(button => {
    button.classList.toggle("selected", button.dataset.evidenceId === id);
  });

  const detail = document.getElementById("evidenceDetail");
  detail.replaceChildren();

  const eyebrow = document.createElement("div");
  eyebrow.className = "eyebrow";
  eyebrow.textContent = "SELECTED EVIDENCE";

  const title = document.createElement("h3");
  title.textContent = item.title;

  const description = document.createElement("p");
  description.textContent = item.description;

  const source = document.createElement("p");
  source.textContent = `Source: ${item.source}`;

  detail.append(eyebrow, title, description, source);

  if (item.snippet) {
    const snippet = document.createElement("code");
    snippet.textContent = item.snippet;
    detail.append(snippet);
  }

  const note = document.createElement("p");
  note.textContent = item.confidenceNote;
  detail.append(note);
}

function renderEvidence(evidence) {
  const list = document.getElementById("evidenceList");
  if (!list) return;
  list.replaceChildren();

  evidence.forEach((item, index) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `evidence-item${index === 0 ? " selected" : ""}`;
    button.dataset.evidenceId = item.id;

    const title = document.createElement("strong");
    title.textContent = item.title;

    const type = document.createElement("small");
    type.textContent = `${item.type} · ${item.id}`;

    button.append(title, type);
    button.addEventListener("click", () => showEvidence(item.id));
    list.append(button);
  });

  if (evidence.length) showEvidence(evidence[0].id);
}

function renderApp(data) {
  if (!data) return;
  renderSummary(data);
  renderComponents(data.components || []);
  renderAttackPath(data.attackPaths?.[0]);
  renderEvidence(data.evidence || []);
}

document.getElementById("refreshButton")?.addEventListener("click", () => renderApp(demoData));
document.getElementById("evidenceButton")?.addEventListener("click", () => {
  document.getElementById("evidence")?.scrollIntoView({ behavior: "smooth" });
});

renderApp(demoData);
