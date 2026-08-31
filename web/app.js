const projects = [
  { name: 'web-portal', status: 'ALLOW', files: ['src', 'app.ts', 'auth.ts', 'package.json'] },
  { name: 'legacy-api', status: 'DENY', files: [] },
];
const findings = [
  { id: '01_sql_injection', severity: 'high', confidence: 'medium', message: '37번줄 7에서 취약점 탐지' },
  { id: '23_secret', severity: 'high', confidence: 'high', message: '비밀번호가 하드코딩 되었습니다.' },
  { id: '24_crypto', severity: 'low', confidence: 'high', message: '키 길이가 충분하지 않습니다.' },
];
const fallbackRules = [
  ['KISA-INPUT-01', 'Injection', 'SQL 삽입', true], ['KISA-INPUT-02', 'Execution', '코드 삽입', true],
  ['KISA-INPUT-03', 'File', '경로 조작 및 자원 삽입', true], ['KISA-INPUT-04', 'Browser', '크로스 사이트 스크립트', false],
  ['KISA-INPUT-05', 'Command', '운영체제 명령어 삽입', false], ['KISA-SEC-01', 'Auth', '적절한 인증 없는 중요기능 허용', true],
  ['KISA-SEC-06', 'Secret', '하드코딩된 중요정보', true], ['KISA-TIME-01', 'Race', '경쟁조건: 검사 시점과 사용 시점', false],
];
let rules = fallbackRules.map(([code, tag, name, active]) => ({ code, tag, name, active }));
let kisaGuideRules = [];
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);
const esc = (value) => String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));

function header(title, showActions = false) {
  return `<header class="sub-header"><div><div class="eyebrow">SAST PLATFORM</div><h1 id="page-title">${title}</h1></div>${showActions ? '<div class="header-actions"><span class="done-dot"></span> 완료 <button class="blue-button compact" id="run-button">진단하기</button></div>' : ''}</header>`;
}
function projectPanel() {
  return `<aside class="project-panel"><div class="panel-title">프로젝트 목록</div><div class="project-list">${projects.map((project) => `<div class="project-item ${project.status === 'ALLOW' ? 'allowed' : 'denied'}"><div><b>${esc(project.name)}</b><span class="project-status">${project.status}</span></div>${project.files.map((file) => `<small>⌞　${esc(file)}</small>`).join('')}</div>`).join('')}</div><button class="outline-button project-add" id="project-add">＋ 프로젝트 등록하기</button></aside>`;
}
function severityGauge(severity) { return `<span class="severity-gauge ${severity}"><span>${severity}</span><i></i></span>`; }
function confidenceBadge(confidence) { return `<span class="confidence-badge ${confidence}">${confidence}</span>`; }
function findingsPanel() {
  return `<section class="findings-panel"><div class="file-bar"><span>web-portal\\src\\app.ts</span><button class="filter-button">필터: 시간순　⌄</button></div><div class="table-head"><span>식별자</span><span>심각도</span><span>신뢰도</span><span>메시지</span></div>${findings.map((finding) => `<button class="finding-row" data-finding="${esc(finding.id)}"><strong>${esc(finding.id)}</strong>${severityGauge(finding.severity)}${confidenceBadge(finding.confidence)}<span>${esc(finding.message)}</span></button>`).join('')}</section>`;
}
function dashboard() { return `${header('대시보드', true)}<div class="dashboard-grid">${projectPanel()}${findingsPanel()}</div>`; }
function guide() {
  const catalog = (kisaGuideRules.length ? kisaGuideRules : rules).map((rule) => ({ ...rule, active: rules.find((item) => item.code === rule.code)?.active ?? rule.active }));
  return `${header('KISA 보안 가이드')}<section class="full-panel"><p class="muted">KISA 보안 가이드 정리 문서의 49개 보안약점 항목과 구현 상태를 확인합니다.</p><div class="guide-table"><div class="guide-head"><span>번호</span><span>식별자</span><span>분류</span><span>명칭</span><span>상태</span></div>${catalog.map((rule, index) => `<div class="guide-row"><span>${String(rule.num || index + 1).padStart(2, '0')}</span><b>${esc(rule.code)}</b><span>${esc(rule.category || rule.tag)}</span><span>${esc(rule.name)}</span><em class="state ${rule.active ? 'on' : 'off'}">${rule.active ? '활성' : '비활성'}</em></div>`).join('')}</div></section>`;
}
function history() {
  return `${header('진단 히스토리')}<section class="full-panel"><p class="muted">현재 사용자: admin_sast　·　실행한 정적 진단 기록을 확인합니다.</p><div class="guide-table history-table"><div class="guide-head"><span>탐색시간</span><span>프로젝트 이름</span><span>식별자</span><span>심각도</span><span>신뢰도</span><span>메시지</span></div>${findings.concat(findings).map((finding, index) => `<div class="guide-row"><span>2025-02-14 14:${String(32 + index).padStart(2, '0')}</span><b>web-portal</b><span>${esc(finding.id)}</span>${severityGauge(finding.severity)}${confidenceBadge(finding.confidence)}<span>${esc(finding.message)}</span></div>`).join('')}</div></section>`;
}
function rulesPage() {
  const active = rules.filter((rule) => rule.active);
  const available = (kisaGuideRules.length ? kisaGuideRules : rules).filter((rule) => !active.some((item) => item.code === rule.code));
  return `${header('탐지 규칙 관리')}<section class="rules-page"><div class="rules-page-heading"><p class="muted">현재 진단에 적용된 규칙을 확인하고 KISA 보안 가이드에서 규칙을 추가합니다.</p></div><div class="rules-columns"><section class="rule-panel"><h3>현재 탐지 규칙</h3><p class="muted">진단에 적용 중인 규칙 ${active.length}개</p><div class="rule-list">${active.map((rule) => `<div class="rule-list-row"><b>${esc(rule.code)}</b><span>${esc(rule.tag || rule.category)} · ${esc(rule.name)}</span><button class="outline-button remove-rule" data-rule-code="${esc(rule.code)}">해제</button></div>`).join('') || '<p class="empty-state">적용 중인 규칙이 없습니다.</p>'}</div></section><section class="rule-panel"><h3>KISA 보안 가이드 검색</h3><label class="search-field"><span aria-hidden="true">⌕</span><input id="rule-search" type="search" placeholder="식별자, 명칭으로 검색하세요"></label><div id="available-rules" class="rule-list available-rule-list">${available.slice(0, 12).map((rule) => `<div class="rule-list-row"><div><b>${esc(rule.code)}</b><span>${esc(rule.tag || rule.category)} · ${esc(rule.name)}</span></div><button class="outline-button add-rule" data-rule-code="${esc(rule.code)}">추가</button></div>`).join('')}</div></section></div></section>`;
}
function usersPage() { return `${header('사용자 권한 관리')}<section class="full-panel"><p class="muted">시스템 사용자의 역할과 프로젝트 접근 권한을 관리합니다.</p><div class="user-table"><div class="guide-head"><span>사용자</span><span>아이디</span><span>역할</span><span>상태</span><span>관리</span></div><div class="guide-row"><b>김 관리자</b><span>admin_sast</span><strong>ADMIN</strong><em class="state on">활성</em><button class="outline-button">프로젝트 권한</button></div><div class="guide-row"><b>이 사용자</b><span>user_sast</span><strong>USER</strong><em class="state on">활성</em><button class="outline-button">프로젝트 권한</button></div></div></section>`; }
function languages() { return `${header('진단 언어 관리')}<section class="full-panel language-panel"><div class="page-heading-row"><div><p class="muted">SAST 정적 진단에 사용할 프로그래밍 언어를 관리합니다.</p></div><button class="blue-button compact" id="add-language">＋ 관리 언어 추가</button></div><div class="language-cards">${['Java', 'Javascript', 'Python'].map((language) => `<article><span class="language-icon">⌘</span><h3>${language}</h3><p>기초 대상 언어 · 지원 중</p></article>`).join('')}</div></section>`; }
function bindPageEvents() {
  $('#project-add')?.addEventListener('click', () => openModal('project-modal'));
  $('#run-button')?.addEventListener('click', () => toast('분석 요청이 준비되었습니다.'));
  $('#add-language')?.addEventListener('click', () => toast('새 언어 등록 기능을 준비 중입니다.'));
  document.querySelectorAll('[data-finding]').forEach((button) => { button.onclick = () => openModal('finding-modal'); });
  document.querySelectorAll('.add-rule').forEach((button) => { button.onclick = () => { const rule = (kisaGuideRules.length ? kisaGuideRules : rules).find((item) => item.code === button.dataset.ruleCode); if (rule && !rules.some((item) => item.code === rule.code)) rules.push({ ...rule, active: true }); render('rules'); }; });
  document.querySelectorAll('.remove-rule').forEach((button) => { button.onclick = () => { rules = rules.map((rule) => rule.code === button.dataset.ruleCode ? { ...rule, active: false } : rule); render('rules'); }; });
  $('#rule-search')?.addEventListener('input', (event) => { const query = event.target.value.toLowerCase(); document.querySelectorAll('#available-rules .rule-list-row').forEach((row) => { row.hidden = !row.textContent.toLowerCase().includes(query); }); });
}
function render(page = 'dashboard') { const views = { dashboard, guide, history, rules: rulesPage, users: usersPage, languages }; $('#page-root').innerHTML = (views[page] || dashboard)(); $('#page-title').dataset.page = page; document.querySelectorAll('[data-page]').forEach((button) => button.classList.toggle('active', button.dataset.page === page)); bindPageEvents(); }
function openModal(id) { $('#' + id)?.classList.remove('hidden'); }
function closeModals() { $$('.modal-backdrop').forEach((modal) => modal.classList.add('hidden')); }
function toast(message) { const toastElement = document.createElement('div'); toastElement.className = 'toast'; toastElement.textContent = message; document.body.append(toastElement); setTimeout(() => toastElement.remove(), 2200); }
function parseKisaGuide(text) { return text.trim().split(/\r?\n/).map((line) => { const match = line.match(/^(\d+)\s+(\S+)\s+(\S+)\s+(.+)$/); return match ? { num: Number(match[1]), code: match[2], category: match[3], name: match[4], active: false } : null; }).filter(Boolean); }
fetch('/kisa-guide.txt').then((response) => response.ok ? response.text() : Promise.reject()).then((text) => { kisaGuideRules = parseKisaGuide(text); if ($('#page-title')?.dataset.page === 'guide') render('guide'); if ($('#page-title')?.dataset.page === 'rules') render('rules'); }).catch(() => {});
$('#login-form').onsubmit = (event) => { event.preventDefault(); $('#login-view').classList.add('hidden'); $('#app-view').classList.remove('hidden'); render(); };
$('#signup-form').onsubmit = (event) => { event.preventDefault(); toast('회원가입 화면은 목업 상태입니다.'); $('#signup-view').classList.add('hidden'); $('#login-view').classList.remove('hidden'); };
$('#show-signup').onclick = () => { $('#login-view').classList.add('hidden'); $('#signup-view').classList.remove('hidden'); }; $('#show-login').onclick = () => { $('#signup-view').classList.add('hidden'); $('#login-view').classList.remove('hidden'); };
$('#toggle-password').onclick = () => { $('#login-password').type = $('#login-password').type === 'password' ? 'text' : 'password'; };
$('#menu-button').onclick = () => { $('#slide-menu').classList.toggle('open'); $('#page-dimmer').classList.toggle('show'); }; $('#page-dimmer').onclick = () => { $('#slide-menu').classList.remove('open'); $('#page-dimmer').classList.remove('show'); };
document.querySelectorAll('[data-page]').forEach((button) => button.onclick = () => { render(button.dataset.page); $('#slide-menu').classList.remove('open'); $('#page-dimmer').classList.remove('show'); });
$('#profile-button').onclick = () => openModal('profile-modal'); $('#profile-close').onclick = closeModals; $('#menu-logout').onclick = () => location.reload(); document.querySelectorAll('.modal-close').forEach((button) => button.onclick = closeModals);
$('#fake-upload').onclick = () => $('#file-input').click(); $('#file-input').onchange = (event) => { if (event.target.files[0]) { toast(`${event.target.files[0].name} 파일이 선택되었습니다.`); closeModals(); } }; document.querySelectorAll('.modal-backdrop').forEach((modal) => modal.onclick = (event) => { if (event.target === modal) closeModals(); });
