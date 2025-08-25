async function loadReport() {
  const url = '/reports/report.json';
  const resp = await fetch(url, {cache: 'no-store'});
  if (!resp.ok) {
    document.getElementById('meta').innerText = 'No report found. Run the crawler via Actions.';
    return;
  }
  const data = await resp.json();
  document.getElementById('raw-json').innerText = JSON.stringify(data, null, 2);

  const pages = data.pages || [];
  const issues = pages.flatMap(p => p.issues || []);
  const counts = issues.reduce((acc, it) => { acc[it.severity] = (acc[it.severity]||0)+1; return acc; }, {});
  document.getElementById('meta').innerHTML = `<p>Pages crawled: ${pages.length} — Issues: ${issues.length}</p><p>By severity: ${JSON.stringify(counts)}</p>`;

  const tbody = document.querySelector('#issues-table tbody');
  tbody.innerHTML = '';
  const render = (row) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${row.severity}</td><td>${row.category}</td><td>${row.url}</td><td>${row.description}</td><td>${row.evidence||''}</td>`;
    return tr;
  };
  issues.forEach(i => tbody.appendChild(render(i)));
}

document.getElementById('refresh').addEventListener('click', loadReport);
document.getElementById('severity-filter').addEventListener('change', function(e){
  const raw = document.getElementById('raw-json').innerText;
  if (!raw) return;
  const data = JSON.parse(raw);
  const sev = e.target.value;
  const pages = data.pages || [];
  const issues = pages.flatMap(p => p.issues || []);
  const tbody = document.querySelector('#issues-table tbody');
  tbody.innerHTML = '';
  issues.filter(i => sev === 'all' ? true : i.severity === sev).forEach(i=>{
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${i.severity}</td><td>${i.category}</td><td>${i.url}</td><td>${i.description}</td><td>${i.evidence||''}</td>`;
    tbody.appendChild(tr);
  });
});

loadReport().catch(err => { console.error(err); document.getElementById('meta').innerText = 'Failed to load report.' });
