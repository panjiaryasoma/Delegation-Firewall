"use strict";
const $ = (id) => document.getElementById(id);
const state = {plan: null, approved: false, busy: false};
const intentEl = $("intent");
const scopeEl = $("scope-content");
const capLabels = {
  "email.read": "Read inbox", "email.send": "Send email", "email.delete": "Delete email",
  "calendar.create": "Create event", "calendar.read": "Read calendar", "calendar.delete": "Delete event"
};
function setStage(n) {
  for (let i = 1; i <= 4; i++) $("stage-"+i).classList.toggle("selected", i <= n);
}
function errorAt(id, msg) { const el = $(id); el.textContent = msg; el.hidden = !msg; }
function element(tag, className, text) { const n=document.createElement(tag); if(className)n.className=className; if(text!==undefined)n.textContent=String(text); return n; }
async function request(path, options={}) {
  const response = await fetch(path, {headers:{"Content-Type":"application/json"},...options});
  let json;
  try { json = await response.json(); } catch { throw new Error("Server returned invalid JSON"); }
  if (!response.ok) throw new Error(typeof json.detail === "string" ? json.detail : `HTTP ${response.status}`);
  return json;
}
async function status() {
  try {
    const json = await request("/api/health");
    const mode = json.mode === "SIMULATED" ? "Offline demo · No model calls" : json.mode === "NEBIUS_CONFIGURED" ? "Nebius configured" : "Nebius key required";
    $("system-status").textContent = mode;
    $("status-dot").classList.toggle("online", json.mode !== "NO_API_KEY");
  } catch { $("system-status").textContent = "Backend unavailable"; }
}
function invalidate() {
  state.plan = null; state.approved = false;
  scopeEl.hidden = true; $("scope-empty").hidden = false;
  $("policy-state").className = "pill pending"; $("policy-state").textContent = "NOT ANALYZED";
  $("approve-check").checked=false; $("execute").disabled=true;
  setStage(1); errorAt("plan-error", ""); errorAt("run-error", "");
}
function makeCapability(name, selected) {
  const label=element("label", "capability"+(selected ? "" : " off"));
  if (selected) {
    const input=document.createElement("input");input.type="checkbox";input.className="cap-checkbox";input.value=name;input.checked=true;
    input.addEventListener("change", () => {$("approve-check").checked=false; updateExecute();});label.append(input);
  } else {label.append(element("span","x","×"));}
  label.append(element("span","",capLabels[name] || name));
  label.title=name;
  return label;
}
function updateExecute() { $("execute").disabled = state.busy || !$('approve-check').checked || !state.plan; }
function showPlan(plan) {
  state.plan=plan;scopeEl.hidden=false;$("scope-empty").hidden=true;
  $("policy-state").className="pill ready";$("policy-state").textContent="READY FOR APPROVAL";
  $("scope-reason").textContent=plan.reason;
  $("required-count").textContent=plan.proposed_capabilities.length;
  $("required-permissions").replaceChildren(...plan.proposed_capabilities.map(c=>makeCapability(c,true)));
  $("unused-permissions").replaceChildren(...plan.not_required.map(c=>makeCapability(c,false)));
  $("scope-mode").textContent = plan.mode === "SIMULATED" ?
    "OFFLINE SIMULATION: No Nebius inference is being performed. Not valid as evidence of model integration." :
    `LIVE INFERENCE: ${plan.model} via Nebius Token Factory.`;
  $("approve-check").checked=false;setStage(2);updateExecute();
}
async function analyze() {
  const intent=intentEl.value.trim();
  if (intent.length < 20) {errorAt("plan-error","Intent must contain at least 20 characters.");return;}
  invalidate();state.busy=true;$("analyze").disabled=true;$("analyze").firstElementChild.textContent="Analyzing…";
  try { const plan=await request("/api/plan",{method:"POST",body:JSON.stringify({intent})});showPlan(plan); }
  catch(e) {errorAt("plan-error",e.message);}
  finally {state.busy=false;$("analyze").disabled=false;$("analyze").firstElementChild.textContent="Analyze permissions";}
}
function eventRow(entry) {
  const row=element("div","event");const title=element("div","");
  title.append(element("div","event-code",`${String(entry.index).padStart(2,"0")}  ${entry.action}`));
  title.append(element("div","event-sub",entry.detail));
  row.append(title, element("span","actor",entry.actor));
  row.append(element("span","verdict "+entry.verdict.toLowerCase(),entry.verdict));
  return row;
}
function showResult(result) {
  $("activity-empty").hidden=true;$("activity-results").hidden=false;
  $("allowed-number").textContent=result.allowed_count;$("blocked-number").textContent=result.blocked_count;
  $("task-status").textContent=result.completed ? "COMPLETED" : "INCOMPLETE";
  $("task-status").style.color=result.completed ? "#26764e" : "#ae453d";
  $("run-mode").textContent=result.mode === "SIMULATED" ? "SIMULATED" : "NEMOTRON / LIVE";
  $("events").replaceChildren(...result.events.map(eventRow));
  $("audit-digest").textContent=result.audit_digest;
  const items=result.calendar.length ? result.calendar.map(c=>{
    const card=element("div","calendar-card");card.append(element("b","",c.title),element("span","",c.date));return card;
  }) : [element("div","calendar-card","No calendar event created.")];
  $("calendar-items").replaceChildren(...items);
  if(result.agent_error)errorAt("run-error",result.agent_error);
  setStage(4);$("activity").scrollIntoView({behavior:"smooth",block:"start"});
}
async function execute() {
  if (!state.plan || !$("approve-check").checked || state.busy)return;
  state.busy=true;setStage(3);errorAt("run-error","");
  $("execute").disabled=true;$("execute").firstChild.textContent="Executing… ";
  const selected=Array.from(document.querySelectorAll(".cap-checkbox:checked")).map(el=>el.value);
  try {
    const result=await request("/api/run",{method:"POST",body:JSON.stringify({
      plan_token:state.plan.plan_token,approved_capabilities:selected,scenario:$("scenario").value
    })});showResult(result);
  } catch(e) {errorAt("run-error",e.message);setStage(2);}
  finally {state.busy=false;$("execute").firstChild.textContent="Execute in sandbox ";updateExecute();}
}
intentEl.addEventListener("input",()=>{$("char-count").textContent=intentEl.value.length+" / 500";invalidate();});
$("char-count").textContent=intentEl.value.length+" / 500";
$("analyze").addEventListener("click",analyze);
$("execute").addEventListener("click",execute);
$("approve-check").addEventListener("change",updateExecute);
for(const chip of document.querySelectorAll(".chip"))chip.addEventListener("click",()=>{
  intentEl.value=chip.dataset.preset==="deadline" ? "Read my hackathon emails and add the submission deadline to my calendar." : "Read the emails in my inbox and summarize which ones mention a hackathon deadline.";
  intentEl.dispatchEvent(new Event("input"));
});
status();
