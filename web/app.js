const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
const state = { currentUser: null, projects: [], rules: [], languages: [], users: [], members: {}, runs: [], findings: [], currentProject: null, projectFiles: [], selectedFinding: null, permissionUser: null, findingFilter: { sort: 'severity', severity: 'ALL' } };
const SEVERITY_RANK = { HIGH: 0, MEDIUM: 1, LOW: 2 };
function visibleFindings() {
  const f = state.findingFilter;
  let list = state.findings.slice();
  if (f.severity !== 'ALL') list = list.filter((x) => String(x.severity).toUpperCase() === f.severity);
  const byConfidence = (a, b) => Number(b.confidence) - Number(a.confidence);
  if (f.sort === 'severity') list.sort((a, b) => (SEVERITY_RANK[String(a.severity).toUpperCase()] ?? 3) - (SEVERITY_RANK[String(b.severity).toUpperCase()] ?? 3) || byConfidence(a, b));
  else if (f.sort === 'confidence') list.sort(byConfidence);
  else if (f.sort === 'location') list.sort((a, b) => String(a.file_path).localeCompare(String(b.file_path)) || (Number(a.line_number) - Number(b.line_number)));
  return list;
}
const slugOf = (finding) => finding.raw_result?.slug || finding.rule_code_snapshot;
const colOf = (finding) => finding.raw_result?.column || 1;
let authToken = sessionStorage.getItem('sast_token');

async function api(path, options = {}) {
  const headers = options.body instanceof FormData ? { ...(options.headers || {}) } : { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (authToken) headers.Authorization = `Bearer ${authToken}`;
  const response = await fetch(path, { ...options, headers });
  const body = response.status === 204 ? null : await response.json().catch(() => null);
  if (response.status === 401 && authToken) { logout(); throw new Error('세션이 만료되었습니다. 다시 로그인하세요.'); }
  if (!response.ok) throw new Error(body?.error || '요청을 처리하지 못했습니다.');
  return body;
}
const isAdmin = () => state.currentUser?.role === 'ADMIN' || state.currentUser?.role?.value === 'ADMIN';
function header(title, showActions = false) { return `<header class="sub-header"><div><div class="eyebrow">SAST PLATFORM</div><h1 id="page-title">${title}</h1></div>${showActions ? `<div class="header-actions"><span class="done-dot"></span> 완료 ${isAdmin() ? '<button class="blue-button compact" id="run-button">진단하기</button>' : ''}</div>` : ''}</header>`; }
function fileTree(files) {
  if (!files.length) return '<div class="file-tree"><div class="tree-node empty">파일이 없습니다.</div></div>';
  const root = {};
  files.forEach((file) => { let node = root; file.path.split('/').forEach((seg, index, parts) => { node.children = node.children || {}; node = node.children[seg] = node.children[seg] || { name: seg, leaf: index === parts.length - 1 }; }); });
  const walk = (node, depth) => Object.values(node.children || {}).sort((a, b) => (Number(!!a.leaf) - Number(!!b.leaf)) || a.name.localeCompare(b.name)).map((child) => `<div class="tree-node ${child.leaf ? 'file' : 'dir'}" style="padding-left:${8 + depth * 12}px">${child.leaf ? '📄' : '📁'}　${esc(child.name)}</div>${walk(child, depth + 1)}`).join('');
  return `<div class="file-tree">${walk(root, 0)}</div>`;
}
function projectPanel() {
  if (!state.projects.length) return `<aside class="project-panel"><div class="panel-title">프로젝트 목록</div><p class="empty-state">등록된 프로젝트가 없습니다.</p><button class="outline-button project-add" id="project-add">＋ 프로젝트 등록하기</button></aside>`;
  const canManage = state.currentUser?.role === 'ADMIN' || state.currentUser?.role?.value === 'ADMIN';
  return `<aside class="project-panel"><div class="panel-title">프로젝트 목록</div><div class="project-list">${state.projects.map((project) => { const selected = state.currentProject?.project_id === project.project_id; return `<div class="project-row"><button class="project-item allowed ${selected ? 'selected' : ''}" data-project-id="${project.project_id}"><div><b>📁　${esc(project.name)}</b><span class="project-status">ALLOW</span></div></button>${canManage ? `<button class="project-delete" data-project-id="${project.project_id}" aria-label="프로젝트 삭제" title="프로젝트 삭제">🗑</button>` : ''}</div>${selected ? fileTree(state.projectFiles) : ''}`; }).join('')}</div><button class="outline-button project-add" id="project-add">＋ 프로젝트 등록하기</button></aside>`;
}
function severityGauge(severity) { const value = String(severity || 'MEDIUM').toLowerCase(); return `<span class="severity-gauge ${value}"><span>${value}</span><i></i></span>`; }
function confidenceBadge(confidence) { const value = Number(confidence); const type = value >= .8 ? 'high' : value >= .5 ? 'medium' : 'low'; return `<span class="confidence-badge ${type}">${type}</span>`; }
const SORT_LABELS = { severity: '심각도순', confidence: '신뢰도순', location: '파일 위치순' };
function filterMenu() {
  const f = state.findingFilter;
  const opt = (kind, value, label) => `<button class="filter-opt ${f[kind] === value ? 'on' : ''}" data-kind="${kind}" data-value="${value}">${label}</button>`;
  return `<div class="filter-menu hidden" id="filter-menu">
    <div class="filter-group"><span>정렬</span>${Object.entries(SORT_LABELS).map(([k, v]) => opt('sort', k, v)).join('')}</div>
    <div class="filter-group"><span>심각도</span>${opt('severity', 'ALL', '전체')}${['HIGH', 'MEDIUM', 'LOW'].map((s) => opt('severity', s, s)).join('')}</div>
  </div>`;
}
function findingsPanel() {
  const rows = visibleFindings();
  const f = state.findingFilter;
  const currentPath = state.selectedFinding ? state.selectedFinding.file_path : (rows[0]?.file_path || '진단 결과를 선택하세요');
  const label = `${SORT_LABELS[f.sort]}${f.severity === 'ALL' ? '' : ' · ' + f.severity}`;
  const total = state.findings.length;
  const empty = total ? '조건에 맞는 진단 결과가 없습니다.' : '표시할 진단 결과가 없습니다.';
  return `<section class="findings-panel"><div class="file-bar"><span>⌞　${esc(currentPath)}</span><div class="filter-wrap"><button class="filter-button" id="filter-toggle">필터: ${label}　⌄</button>${filterMenu()}</div></div><div class="table-head"><span>식별자</span><span>심각도</span><span>신뢰도</span><span>메세지</span></div><div class="finding-scroll">${rows.map((finding) => `<button class="finding-row ${state.selectedFinding?.finding_id === finding.finding_id ? 'active' : ''}" data-finding-id="${finding.finding_id}"><strong>${esc(slugOf(finding))}</strong>${severityGauge(finding.severity)}${confidenceBadge(finding.confidence)}<span>${esc(finding.message)}</span></button>`).join('') || `<p class="empty-state">${empty}</p>`}</div></section>`;
}
function severityBadge(severity) { const value = String(severity || 'MEDIUM').toLowerCase(); const cls = value === 'high' ? 'high' : value === 'low' ? 'low' : 'medium'; return `<span class="badge ${cls}">${value}</span>`; }
function detailPanel(finding) {
  return `<aside class="detail-panel"><div class="detail-head"><div class="eyebrow">취약점 상세</div><button class="detail-close" id="detail-close" aria-label="닫기">×</button></div><h3>${esc(finding.raw_result?.kisa_code || finding.rule_code_snapshot)}</h3><div class="detail-row"><span>KISA 식별번호</span><b>${esc(finding.rule_code_snapshot)}</b></div><div class="detail-grid"><div><span>심각도</span>${severityBadge(finding.severity)}</div><div><span>신뢰도</span>${confidenceBadge(finding.confidence)}</div></div><div class="detail-row"><span>파일 경로</span><b>${esc(finding.file_path)}</b></div><div class="detail-row"><span>오류 위치</span><b>${finding.line_number}번줄 ${colOf(finding)}열</b></div><div class="detail-label">오류 코드</div><pre class="code-box">${esc(finding.evidence || '-')}</pre><div class="detail-label">세부 메세지</div><p class="detail-message">${esc(finding.message)}</p></aside>`;
}
function dashboard() { return `${header('대시보드', true)}<div class="dashboard-grid ${state.selectedFinding ? 'with-detail' : ''}">${projectPanel()}${findingsPanel()}${state.selectedFinding ? detailPanel(state.selectedFinding) : ''}</div>`; }
function guide() { return `${header('KISA 보안 가이드')}<section class="full-panel"><p class="muted">KISA 보안 가이드의 49개 보안약점 항목과 구현 상태를 확인합니다.</p><div class="guide-table"><div class="guide-head"><span>번호</span><span>식별자</span><span>분류</span><span>명칭</span><span>상태</span></div>${state.rules.map((rule) => `<div class="guide-row"><span>${String(rule.kisa_num || '').padStart(2, '0')}</span><b>${esc(rule.rule_code)}</b><span>${esc(rule.category)}</span><span>${esc(rule.name)}</span><em class="state ${rule.is_active ? 'on' : 'off'}">${rule.is_active ? '활성' : '비활성'}</em></div>`).join('')}</div></section>`; }
function history() { const entries = state.runs.flatMap((run) => (run.findings || []).map((finding) => ({ ...finding, run }))); return `${header('진단 히스토리')}<section class="full-panel"><p class="muted">현재 사용자: admin_sast　·　실행한 정적 진단 기록을 확인합니다.</p><div class="guide-table history-table"><div class="guide-head"><span>탐색시간</span><span>프로젝트 이름</span><span>식별자</span><span>심각도</span><span>신뢰도</span><span>메시지</span></div>${entries.map((entry) => `<div class="guide-row"><span>${esc(entry.run.ended_at || entry.run.started_at || '-')}</span><b>${esc(entry.run.project_name)}</b><span>${esc(entry.rule_code_snapshot)}</span>${severityGauge(entry.severity)}${confidenceBadge(entry.confidence)}<span>${esc(entry.message)}</span></div>`).join('') || '<p class="empty-state">진단 히스토리가 없습니다.</p>'}</div></section>`; }
function rulesPage() { const implemented = state.rules.filter((rule) => rule.is_implemented); const active = implemented.filter((rule) => rule.is_active); const available = implemented.filter((rule) => !rule.is_active); const canManage = state.currentUser?.role === 'ADMIN' || state.currentUser?.role?.value === 'ADMIN'; const action = canManage ? (rule, activeState, label) => `<button class="outline-button rule-toggle" data-rule-id="${rule.rule_id}" data-active="${activeState}">${label}</button>` : ''; return `${header('탐지 규칙 관리')}<section class="rules-page"><div class="rules-page-heading"><p class="muted">진단 엔진에 구현된 규칙만 표시됩니다. 현재 탐지 규칙에 올린 규칙만 실제 진단에 적용됩니다.${canManage ? '' : ' 일반 사용자는 읽기 전용입니다.'}</p></div><div class="rules-columns"><section class="rule-panel"><h3>현재 탐지 규칙</h3><p class="muted">진단에 적용 중인 규칙 ${active.length}개</p><div class="rule-list">${active.map((rule) => `<div class="rule-list-row"><b>${esc(rule.rule_code)}</b><span>${esc(rule.category)} · ${esc(rule.name)}</span>${action(rule, false, '해제')}</div>`).join('') || '<p class="empty-state">적용 중인 규칙이 없습니다.</p>'}</div></section><section class="rule-panel"><h3>추가할 수 있는 규칙</h3><p class="muted">구현되어 있지만 아직 적용하지 않은 규칙 ${available.length}개</p><label class="search-field"><span aria-hidden="true">⌕</span><input id="rule-search" type="search" placeholder="식별자, 명칭으로 검색하세요"></label><div id="available-rules" class="rule-list available-rule-list">${available.slice(0, 20).map((rule) => `<div class="rule-list-row"><div><b>${esc(rule.rule_code)}</b><span>${esc(rule.category)} · ${esc(rule.name)}</span></div>${action(rule, true, '추가')}</div>`).join('') || '<p class="empty-state">추가할 수 있는 규칙이 없습니다.</p>'}</div></section></div></section>`; }
function usersPage() { const canManage = state.currentUser?.role === 'ADMIN' || state.currentUser?.role?.value === 'ADMIN'; return `${header('사용자 권한 관리')}<section class="full-panel"><p class="muted">현재 이용 중인 사용자를 확인하고 프로젝트 접근 권한을 수정합니다.</p><div class="user-table"><div class="guide-head"><span>사용자</span><span>아이디</span><span>역할</span><span>상태</span><span>권한 수정</span></div>${state.users.map((user) => { const role = user.role?.value || user.role; return `<div class="guide-row"><b>${esc(user.username)}</b><span>${esc(user.user_id)}</span><strong>${esc(role === 'ADMIN' ? '관리자' : '일반 사용자')}</strong><em class="state ${user.is_active ? 'on' : 'off'}">${user.is_active ? '활성' : '비활성'}</em><div>${canManage ? `<button class="outline-button permission-edit" data-user-id="${user.user_id}">권한 수정</button>` : '<span class="muted">읽기 전용</span>'}</div></div>`; }).join('')}</div></section>`; }
function permissionModalBody() {
  const user = state.users.find((item) => String(item.user_id) === String(state.permissionUser));
  if (!user) return '';
  const role = user.role?.value || user.role;
  const isMember = (project) => (state.members[project.project_id] || []).some((member) => String(member.user_id) === String(user.user_id));
  const allowed = state.projects.filter(isMember);
  const denied = state.projects.filter((project) => !isMember(project));
  const row = (project, granted) => `<div class="perm-row ${granted ? 'allowed' : 'denied'}"><b>📁　${esc(project.name)}</b><button class="outline-button perm-set" data-project-id="${project.project_id}" data-granted="${granted}">${granted ? '권한 해제' : '권한 부여'}</button></div>`;
  const section = (label, cls, list, granted) => `<div class="perm-section"><span class="perm-label ${cls}">${label} ${list.length}</span>${list.map((project) => row(project, granted)).join('') || '<p class="empty-state">해당 프로젝트가 없습니다.</p>'}</div>`;
  return `<button class="modal-close" id="permission-close" aria-label="닫기">×</button><div class="eyebrow">프로젝트 권한 수정</div><h2>${esc(user.username)}</h2><p class="muted">대상 사용자 · ${esc(user.username)}　(${role === 'ADMIN' ? '관리자' : '일반 사용자'})</p><hr>${role === 'ADMIN' ? '<p class="muted">관리자는 모든 프로젝트에 접근할 수 있습니다.</p>' : ''}${section('접근 가능한 프로젝트', 'on', allowed, true)}${section('접근할 수 없는 프로젝트', 'off', denied, false)}`;
}
async function renderPermissionModal() {
  const body = $('#permission-modal-body');
  if (!body) return;
  body.innerHTML = permissionModalBody();
  body.querySelector('#permission-close')?.addEventListener('click', closeModals);
  body.querySelectorAll('.perm-set').forEach((button) => button.addEventListener('click', async () => {
    const projectId = button.dataset.projectId;
    const granted = button.dataset.granted === 'true';
    button.disabled = true;
    try {
      await api(`/api/projects/${projectId}/members`, { method: granted ? 'DELETE' : 'POST', body: JSON.stringify({ user_id: Number(state.permissionUser) }) });
      state.members[projectId] = await api(`/api/projects/${projectId}/members`);
      await renderPermissionModal();
    } catch (error) { toast(error.message); button.disabled = false; }
  }));
}
async function openPermissionModal(userId) { state.permissionUser = userId; await renderPermissionModal(); openModal('permission-modal'); }
function languages() { return `${header('진단 언어 관리')}<section class="full-panel language-panel"><div class="page-heading-row"><div><p class="muted">SAST 정적 진단에 사용할 프로그래밍 언어를 관리합니다.</p></div><button class="blue-button compact" id="add-language">＋ 관리 언어 추가</button></div><div class="language-cards">${state.languages.map((language) => `<article><span class="language-icon">⌘</span><h3>${esc(language.display_name)}</h3><p>${language.is_active ? '지원 중' : '비활성'}</p><button class="outline-button language-toggle" data-language="${esc(language.language_code)}" data-active="${!language.is_active}">${language.is_active ? '비활성화' : '활성화'}</button></article>`).join('')}</div></section>`; }

async function loadProjects() { state.projects = await api('/api/projects'); if (!state.currentProject || !state.projects.some((p) => p.project_id === state.currentProject.project_id)) { state.currentProject = state.projects[0] || null; state.selectedFinding = null; } await loadProjectResults(); }
async function loadProjectResults() { state.runs = []; state.findings = []; state.projectFiles = []; if (!state.currentProject) return; const id = state.currentProject.project_id; state.projectFiles = await api(`/api/projects/${id}/files`).catch(() => []); const runs = await api(`/api/projects/${id}/runs`); state.runs = await Promise.all(runs.map(async (run) => ({ ...run, project_name: state.currentProject.name, findings: await api(`/api/projects/${id}/runs/${run.run_id}/findings`) }))); state.findings = state.runs[0]?.findings || []; if (state.selectedFinding && !state.findings.some((f) => f.finding_id === state.selectedFinding.finding_id)) state.selectedFinding = null; }
async function loadHistory() { state.projects = await api('/api/projects'); state.runs = (await Promise.all(state.projects.map(async (project) => { const runs = await api(`/api/projects/${project.project_id}/runs`); return Promise.all(runs.map(async (run) => ({ ...run, project_name: project.name, findings: await api(`/api/projects/${project.project_id}/runs/${run.run_id}/findings`) }))); }))).flat(); }
async function loadPageData(page) { if (page === 'dashboard') await loadProjects(); if (page === 'guide' || page === 'rules') state.rules = await api('/api/rules'); if (page === 'languages') state.languages = await api('/api/languages'); if (page === 'users') { state.users = await api('/api/users'); state.projects = await api('/api/projects'); state.members = Object.fromEntries(await Promise.all(state.projects.map(async (project) => [project.project_id, await api(`/api/projects/${project.project_id}/members`)]))); } if (page === 'history') await loadHistory(); }
async function render(page = 'dashboard') { try { await loadPageData(page); const views = { dashboard, guide, history, rules: rulesPage, users: usersPage, languages }; $('#page-root').innerHTML = (views[page] || dashboard)(); $('#page-title').dataset.page = page; document.querySelectorAll('[data-page]').forEach((button) => button.classList.toggle('active', button.dataset.page === page)); bindPageEvents(); } catch (error) { toast(error.message); } }
function bindPageEvents() {
  $('#project-add')?.addEventListener('click', () => openModal('project-modal'));
  document.querySelectorAll('.project-item[data-project-id]').forEach((button) => button.addEventListener('click', async () => { const next = state.projects.find((project) => String(project.project_id) === button.dataset.projectId); if (next?.project_id !== state.currentProject?.project_id) { state.currentProject = next; state.selectedFinding = null; } await render('dashboard'); }));
  document.querySelectorAll('.project-delete').forEach((button) => button.addEventListener('click', async (event) => { event.stopPropagation(); const project = state.projects.find((item) => String(item.project_id) === button.dataset.projectId); if (!project || !confirm(`'${project.name}' 프로젝트를 삭제할까요?\n연결된 진단 실행과 결과도 함께 삭제됩니다.`)) return; try { await api(`/api/projects/${button.dataset.projectId}`, { method: 'DELETE' }); if (String(state.currentProject?.project_id) === button.dataset.projectId) { state.currentProject = null; state.selectedFinding = null; } toast('프로젝트가 삭제되었습니다.'); await render('dashboard'); } catch (error) { toast(error.message); } }));
  $('#run-button')?.addEventListener('click', async () => { if (!state.currentProject) return toast('먼저 프로젝트를 등록하세요.'); try { const run = await api(`/api/projects/${state.currentProject.project_id}/analyze`, { method: 'POST', body: '{}' }); state.selectedFinding = null; toast(`진단이 ${run.status === 'COMPLETED' ? '완료' : '실패'}되었습니다.`); await render('dashboard'); } catch (error) { toast(error.message); } });
  document.querySelectorAll('[data-finding-id]').forEach((button) => button.addEventListener('click', () => openFinding(button.dataset.findingId)));
  $('#filter-toggle')?.addEventListener('click', (event) => {
    event.stopPropagation();
    const menu = $('#filter-menu');
    if (!menu) return;
    menu.classList.toggle('hidden');
    if (!menu.classList.contains('hidden')) setTimeout(() => document.addEventListener('click', () => menu.classList.add('hidden'), { once: true }));
  });
  document.querySelectorAll('.filter-opt').forEach((button) => button.addEventListener('click', async (event) => {
    event.stopPropagation();
    state.findingFilter = { ...state.findingFilter, [button.dataset.kind]: button.dataset.value };
    if (state.selectedFinding && !visibleFindings().some((f) => f.finding_id === state.selectedFinding.finding_id)) state.selectedFinding = null;
    await render('dashboard');
  }));
  $('#detail-close')?.addEventListener('click', async () => { state.selectedFinding = null; await render('dashboard'); });
  document.querySelectorAll('.rule-toggle').forEach((button) => button.addEventListener('click', async () => { try { await api(`/api/rules/${button.dataset.ruleId}`, { method: 'PATCH', body: JSON.stringify({ is_active: button.dataset.active === 'true' }) }); await render('rules'); } catch (error) { toast(error.message); } }));
  $('#rule-search')?.addEventListener('input', (event) => { const query = event.target.value.toLowerCase(); document.querySelectorAll('#available-rules .rule-list-row').forEach((row) => { row.hidden = !row.textContent.toLowerCase().includes(query); }); });
  document.querySelectorAll('.language-toggle').forEach((button) => button.addEventListener('click', async () => { try { await api(`/api/languages/${button.dataset.language}`, { method: 'PATCH', body: JSON.stringify({ is_active: button.dataset.active === 'true' }) }); await render('languages'); } catch (error) { toast(error.message); } }));
  document.querySelectorAll('.permission-edit').forEach((button) => button.addEventListener('click', () => openPermissionModal(button.dataset.userId)));
  $('#add-language')?.addEventListener('click', async () => { const name = prompt('추가할 언어 이름을 입력하세요.'); if (!name) return; try { await api('/api/languages', { method: 'POST', body: JSON.stringify({ language_code: name.toUpperCase().replace(/\s+/g, '_'), display_name: name }) }); await render('languages'); } catch (error) { toast(error.message); } });
}
async function openFinding(id) { const finding = state.findings.find((item) => String(item.finding_id) === String(id)); if (!finding) return; state.selectedFinding = state.selectedFinding?.finding_id === finding.finding_id ? null : finding; await render('dashboard'); }
function openModal(id) { $('#' + id)?.classList.remove('hidden'); } function closeModals() { $$('.modal-backdrop').forEach((modal) => modal.classList.add('hidden')); } function toast(message) { const element = document.createElement('div'); element.className = 'toast'; element.textContent = message; document.body.append(element); setTimeout(() => element.remove(), 2500); }
function updateProfile(user) { state.currentUser = user; const role = user.role?.value || user.role; const roleLabel = role === 'ADMIN' ? '시스템 관리자' : '일반 사용자'; const initial = (user.username || '?').slice(0, 1).toUpperCase(); document.querySelectorAll('.profile-button b,.menu-user b').forEach((element) => { element.textContent = user.username; }); document.querySelectorAll('.profile-button span,.menu-user>span,.profile-avatar').forEach((element) => { element.textContent = initial; }); $('.menu-user small').textContent = roleLabel; const modal = $('#profile-modal'); modal.querySelector('h2').textContent = user.username; modal.querySelector('.muted').textContent = roleLabel; const info = modal.querySelectorAll('.profile-info b'); info[0].textContent = user.username; info[1].textContent = roleLabel; info[2].textContent = user.last_login_at ? new Date(user.last_login_at).toLocaleString('ko-KR') : '-'; const isAdmin = role === 'ADMIN'; document.querySelectorAll('[data-page="rules"],[data-page="users"],[data-page="languages"]').forEach((button) => { button.classList.toggle('hidden', !isAdmin); }); }
function logout() { authToken = null; state.currentUser = null; sessionStorage.removeItem('sast_token'); $('#app-view').classList.add('hidden'); $('#login-view').classList.remove('hidden'); }
$('#login-form').onsubmit = async (event) => { event.preventDefault(); $('#login-error').textContent = ''; try { const result = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ username: $('#login-id').value, password: $('#login-password').value }) }); authToken = result.access_token; sessionStorage.setItem('sast_token', authToken); updateProfile(result.user); $('#login-view').classList.add('hidden'); $('#app-view').classList.remove('hidden'); await render('dashboard'); } catch (error) { $('#login-error').textContent = error.message; } };
$('#signup-form').onsubmit = (event) => { event.preventDefault(); toast('회원가입은 관리자 등록 기능으로 제공됩니다.'); $('#signup-view').classList.add('hidden'); $('#login-view').classList.remove('hidden'); }; $('#show-signup').onclick = () => { $('#login-view').classList.add('hidden'); $('#signup-view').classList.remove('hidden'); }; $('#show-login').onclick = () => { $('#signup-view').classList.add('hidden'); $('#login-view').classList.remove('hidden'); }; $('#toggle-password').onclick = () => { $('#login-password').type = $('#login-password').type === 'password' ? 'text' : 'password'; };
$('#menu-button').onclick = () => { $('#slide-menu').classList.toggle('open'); $('#page-dimmer').classList.toggle('show'); }; $('#page-dimmer').onclick = () => { $('#slide-menu').classList.remove('open'); $('#page-dimmer').classList.remove('show'); }; document.querySelectorAll('[data-page]').forEach((button) => button.onclick = () => { render(button.dataset.page); $('#slide-menu').classList.remove('open'); $('#page-dimmer').classList.remove('show'); }); $('#profile-button').onclick = () => openModal('profile-modal'); $('#profile-close').onclick = closeModals; $('#menu-logout').onclick = logout; document.querySelectorAll('.modal-close').forEach((button) => button.onclick = closeModals); document.querySelectorAll('.modal-backdrop').forEach((modal) => modal.onclick = (event) => { if (event.target === modal) closeModals(); });
const DROP_HINT = '여기에 ZIP 파일을 끌어다 놓으세요';
function setDropLabel(file) { const label = $('#drop-label'); if (label) label.textContent = file ? file.name : DROP_HINT; }
(() => { const zone = $('#drop-zone'), input = $('#project-source-file'); if (!zone || !input) return;
  ['dragover', 'dragenter'].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add('drag'); }));
  ['dragleave', 'dragend'].forEach((ev) => zone.addEventListener(ev, () => zone.classList.remove('drag')));
  zone.addEventListener('drop', (e) => { e.preventDefault(); zone.classList.remove('drag'); if (e.dataTransfer.files[0]) { input.files = e.dataTransfer.files; setDropLabel(input.files[0]); } });
  input.addEventListener('change', () => setDropLabel(input.files[0]));
})();
$('#project-form').onsubmit = async (event) => { event.preventDefault(); const file = $('#project-source-file').files[0]; const projectName = $('#project-name').value.trim(); if (!projectName) return toast('프로젝트 이름을 입력해 주세요.'); if (!file) return toast('ZIP 파일을 선택해 주세요.'); if (!file.name.toLowerCase().endsWith('.zip')) return toast('ZIP 파일만 업로드할 수 있습니다.'); const form = new FormData(); form.append('name', projectName); form.append('source_file', file); try { const project = await api('/api/projects', { method: 'POST', body: form }); closeModals(); event.target.reset(); setDropLabel(null); toast('프로젝트가 등록되었습니다.'); state.currentProject = project; state.selectedFinding = null; await render('dashboard'); } catch (error) { toast(error.message); } };
if (authToken) { api('/api/me').then((user) => { updateProfile(user); $('#login-view').classList.add('hidden'); $('#app-view').classList.remove('hidden'); return render('dashboard'); }).catch(() => {}); }
