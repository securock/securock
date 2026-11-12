let token = "";
let generation = 0;
let signedIn = false;
const el = (id) => document.getElementById(id);
async function api(path, method = "GET", body) {
  const response = await fetch("/api/v1/" + path, {
    method,
    headers: {
      ...(token ? { Authorization: "Bearer " + token } : {}),
      "X-Securock-Request": "1",
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!response.ok) {
    if (response.status === 401) throw Error("Sign in to load your workspace.");
    if (response.status === 403)
      throw Error("Your role does not allow this action.");
    if (response.status === 429)
      throw Error("Request limit reached. Try again in one minute.");
    throw Error("Request could not be completed (" + response.status + ").");
  }
  return (await response.json()).data;
}
function cell(row, value) {
  const td = document.createElement("td");
  td.textContent = value || "—";
  row.append(td);
  return td;
}
function action(parent, label, fn, disabled = false) {
  const button = document.createElement("button");
  button.textContent = label;
  button.disabled = disabled;
  button.onclick = async () => {
    button.disabled = true;
    try {
      await fn();
    } catch (error) {
      el("error").textContent = error.message;
    } finally {
      button.disabled = disabled;
    }
  };
  parent.append(button);
}
async function load() {
  const current = generation;
  try {
    const me = await api("me");
    const [projects, jobs, queues, approvals] = await Promise.all([
      api("projects"),
      api("jobs"),
      api("issues"),
      api("approvals"),
    ]);
    if (generation !== current) return;
    signedIn = true;
    const canWrite = me.roles.some((r) => ["admin", "developer"].includes(r));
    const canReview = me.roles.some((r) => ["admin", "reviewer"].includes(r));
    el("who").textContent = me.subject + " · " + me.tenant;
    el("project-form").hidden = !canWrite;
    el("approval-form").hidden = !canWrite;
    el("scan").disabled = !canWrite || projects.length === 0;
    const selected = el("project").value;
    el("project").replaceChildren();
    for (const project of projects) {
      const option = document.createElement("option");
      option.value = project.id;
      option.textContent =
        project.name + (project.owner ? " · " + project.owner : "");
      el("project").append(option);
    }
    if (projects.some((p) => p.id === selected)) el("project").value = selected;
    el("jobs").replaceChildren();
    for (const job of jobs) {
      const row = document.createElement("tr");
      cell(row, job.project);
      cell(row, job.status);
      cell(row, job.created);
      const controls = cell(row, "");
      controls.replaceChildren();
      action(controls, "View results", async () => {
        const details = await api("jobs/" + encodeURIComponent(job.id));
        if (current !== generation) return;
        el("details").textContent = JSON.stringify(details, null, 2);
        el("report").open = true;
      });
      if (["queued", "running"].includes(job.status))
        action(
          controls,
          "Cancel",
          async () => {
            await api("jobs/" + encodeURIComponent(job.id), "DELETE");
            await load();
          },
          !canWrite,
        );
      el("jobs").append(row);
    }
    el("issues").replaceChildren();
    let open = 0;
    for (const [project, registry] of Object.entries(queues)) {
      for (const issue of registry.entries) {
        if (issue.state !== "resolved") open++;
        const row = document.createElement("tr");
        cell(row, project);
        cell(row, issue.state);
        cell(row, issue.finding.severity);
        const title = cell(row, issue.finding.title);
        title.title = issue.finding.remediation || issue.finding.id;
        const controls = cell(row, "");
        controls.replaceChildren();
        const owner = document.createElement("input");
        owner.value = issue.owner || "";
        owner.setAttribute("aria-label", "Finding owner");
        owner.disabled = !canWrite;
        const due = document.createElement("input");
        due.type = "date";
        due.value = issue.due || "";
        due.setAttribute("aria-label", "Finding due date");
        due.disabled = !canWrite;
        controls.append(owner, due);
        action(
          controls,
          "Assign",
          async () => {
            await api("issues/" + encodeURIComponent(project), "PUT", {
              key: issue.key,
              owner: owner.value,
              due: due.value,
            });
            await load();
          },
          !canWrite,
        );
        el("issues").append(row);
      }
    }
    el("approvals").replaceChildren();
    for (const approval of Object.values(approvals)) {
      const row = document.createElement("tr");
      cell(row, approval.rule);
      const artifact = cell(row, approval.artifact.slice(0, 16) + "…");
      artifact.title = approval.artifact;
      cell(row, approval.requester);
      cell(row, approval.status);
      cell(row, approval.expires);
      const controls = cell(row, approval.reviewer || "");
      if (approval.status === "pending") {
        controls.replaceChildren();
        for (const [label, status] of [
          ["Approve", "approved"],
          ["Reject", "rejected"],
        ]) {
          action(
            controls,
            label,
            async () => {
              await api("approvals/" + encodeURIComponent(approval.id), "PUT", {
                status,
              });
              await load();
            },
            !canReview || approval.requester === me.subject,
          );
        }
      }
      el("approvals").append(row);
    }
    el("project-count").textContent = projects.length;
    el("open-count").textContent = open;
    el("queue-count").textContent = jobs.filter((j) =>
      ["queued", "running"].includes(j.status),
    ).length;
    el("error").textContent = "";
  } catch (error) {
    if (current !== generation) return;
    signedIn = false;
    el("error").textContent = error.message;
  }
}
el("login").onclick = () => {
  generation++;
  token = el("token").value;
  el("token").value = "";
  load();
};
el("logout").onclick = async () => {
  generation++;
  token = "";
  signedIn = false;
  try {
    await fetch("/auth/logout", {
      method: "POST",
      headers: { "X-Securock-Request": "1" },
    });
  } finally {
    for (const id of ["jobs", "issues", "approvals", "project"])
      el(id).replaceChildren();
    for (const id of ["project-count", "open-count", "queue-count"])
      el(id).textContent = "0";
    el("details").textContent = "";
    el("who").textContent = "Signed out";
    el("project-form").hidden = true;
    el("approval-form").hidden = true;
    el("scan").disabled = true;
  }
};
el("refresh").onclick = load;
el("create").onclick = async () => {
  try {
    await api("projects", "POST", {
      id: el("projectid").value,
      name: el("name").value,
      owner: el("owner").value,
    });
    await load();
  } catch (error) {
    el("error").textContent = error.message;
  }
};
el("scan").onclick = async () => {
  try {
    await api("jobs", "POST", {
      id: crypto.randomUUID(),
      project: el("project").value,
    });
    await load();
  } catch (error) {
    el("error").textContent = error.message;
  }
};
el("request-approval").onclick = async () => {
  try {
    const expires = new Date(el("expires").value + "Z").toISOString();
    await api("approvals", "POST", {
      id: crypto.randomUUID(),
      artifact: el("artifact").value.trim(),
      rule: el("rule").value.trim(),
      reason: el("reason").value,
      expires,
    });
    await load();
  } catch (error) {
    el("error").textContent = error.message;
  }
};
el("export-audit").onclick = async () => {
  try {
    const audit = await api("audit");
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(audit, null, 2)], { type: "application/json" }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = "securock-audit.json";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) {
    el("error").textContent = error.message;
  }
};
el("expires").value = new Date(Date.now() + 7 * 86400000)
  .toISOString()
  .slice(0, 16);
setInterval(() => {
  if (
    signedIn &&
    !document.hidden &&
    !document.activeElement.matches("input,textarea,select")
  )
    load();
}, 15000);
load();
