import supabase from './supabaseClient.js';

(function(){
  'use strict';

  // ------------------ Admin authentication (secure) ------------------
  const AUTH_KEY = 'adminAuth';
  const LOCKOUT_KEY = 'adminLockout';
  const SESSION_KEY = 'adminSession';

  const textEncoder = new TextEncoder();
  const toBytes = (str) => textEncoder.encode(str);
  const toBase64 = (arrBuf) => btoa(String.fromCharCode(...new Uint8Array(arrBuf)));
  const fromBase64 = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));

  async function deriveKey(password, salt, iterations = 150000) {
    const keyMaterial = await crypto.subtle.importKey('raw', toBytes(password), { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
    const raw = await crypto.subtle.exportKey('raw', key);
    return raw;
  }

  async function hashPassword(password, saltBytes, iterations = 150000) {
    const salt = saltBytes || crypto.getRandomValues(new Uint8Array(16));
    const raw = await deriveKey(password, salt, iterations);
    return { salt: toBase64(salt), iterations, hash: toBase64(raw) };
  }

  async function verifyPassword(password, auth) {
    const salt = fromBase64(auth.salt);
    const raw = await deriveKey(password, salt, auth.iterations);
    const compare = toBase64(raw);
    return compare === auth.hash;
  }

  function getAuth(){ return ls.get(AUTH_KEY, null); }
  function setAuth(v){ ls.set(AUTH_KEY, v); }

  function getLockout(){ return ls.get(LOCKOUT_KEY, { count:0, lockUntil:0 }); }
  function setLockout(v){ ls.set(LOCKOUT_KEY, v); }
  function resetLockout(){ setLockout({ count:0, lockUntil:0 }); }
  function recordFailure(){
    const now = Date.now();
    const state = getLockout();
    const count = (state.count||0) + 1;
    let lockUntil = state.lockUntil||0;
    if(count >= 5){
      const step = Math.min(count - 4, 6); // cap growth
      lockUntil = now + step * 60 * 1000; // minutes
    }
    setLockout({ count, lockUntil });
  }
  function isLockedOut(){
    const st = getLockout();
    return (st.lockUntil||0) > Date.now();
  }

  function hasAuth(){ return !!getAuth(); }

  // ------------------ Utilities ------------------
  const ls = {
    get(key, fallback){
      try { const v = JSON.parse(localStorage.getItem(key)); return v ?? fallback; } catch(e) { return fallback; }
    },
    set(key, value){ localStorage.setItem(key, JSON.stringify(value)); }
  };
  const qs = (sel, el=document) => el.querySelector(sel);
  const qsa = (sel, el=document) => Array.from(el.querySelectorAll(sel));
  const generateId = (prefix='id') => `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2,6)}`;
  const currency = (n) => new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR' }).format(Number(n)||0);
  const formatDate = (ts) => new Date(ts).toLocaleString();
  const debounce = (fn, delay=250) => { let t; return (...args) => { clearTimeout(t); t=setTimeout(()=>fn(...args), delay); }; };
  const upgrade = () => { if(window.componentHandler){ try{ componentHandler.upgradeDom(); }catch(_){} } };

  function showSnack(msg){ const el = qs('#snackbar'); if(el && el.MaterialSnackbar){ el.MaterialSnackbar.showSnackbar({ message: msg }); } }

  // ------------------ Seed defaults if missing (so admin can run standalone) ------------------
  function seedIfNeeded(){
    if(!ls.get('appConfig')){
      ls.set('appConfig', { logo:'', tagline:'Handcrafted Stone & Marble Statues', whatsappNumber:'+919999999999', version:1 });
    }
    if(!ls.get('products')){
      const seed = [
        {name:'Shiva Marble Idol', material:'Marble', dimensions:'24in H x 12in W x 10in D', price:12000, categories:['God Idols','Marble'], image:''},
        {name:'Ganesha Sandstone Idol', material:'Sandstone', dimensions:'18in H x 10in W x 8in D', price:8000, categories:['God Idols','Sandstone'], image:''},
        {name:'Buddha Granite Bust', material:'Granite', dimensions:'16in H x 10in W x 8in D', price:9500, categories:['Busts','Granite'], image:''},
        {name:'Nandi Stone Sculpture', material:'Stone', dimensions:'14in H x 18in W x 12in D', price:11000, categories:['Animals','Stone'], image:''},
        {name:'Radha Krishna Marble Pair', material:'Marble', dimensions:'22in H x 16in W x 10in D', price:20000, categories:['God Idols','Marble'], image:''},
        {name:'Abstract Marble Art Piece', material:'Marble', dimensions:'20in H x 10in W x 6in D', price:15000, categories:['Abstract','Marble'], image:''},
        {name:'Elephant Sandstone Figurine', material:'Sandstone', dimensions:'12in H x 16in W x 8in D', price:7000, categories:['Animals','Sandstone'], image:''},
        {name:'Durga Marble Idol', material:'Marble', dimensions:'26in H x 16in W x 10in D', price:22000, categories:['God Idols','Marble'], image:''},
      ].map(p=>({ id: generateId('prod'), description: `${p.name} handcrafted in ${p.material}.`, ...p }));
      ls.set('products', seed);
    }
    if(!ls.get('users')){ ls.set('users', []); }
    if(!ls.get('orders')){ ls.set('orders', []); }
  }

  // ------------------ Session ------------------
  function getSession(){ return ls.get(SESSION_KEY, null); }
  function setSession(v){ ls.set(SESSION_KEY, v); }
  function clearSession(){ localStorage.removeItem(SESSION_KEY); }

  function isLoggedIn(){
    const s = getSession();
    if(!s) return false;
    if((s.expiresAt||0) < Date.now()){ clearSession(); return false; }
    return true;
  }

  function createToken(){
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    return Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join('');
  }

  function refreshSession(){
    const s = getSession();
    if(!s) return;
    const extended = { ...s, expiresAt: Date.now() + 30*60*1000, lastActivity: Date.now() };
    setSession(extended);
  }

  function setupSessionKeepAlive(){
    const handler = debounce(refreshSession, 60000);
    ['click','keydown','mousemove','scroll','touchstart'].forEach(evt => {
      window.addEventListener(evt, handler, { passive:true });
    });
  }

  async function login(email, password){
    if(isLockedOut()){
      return { ok:false, reason:'locked' };
    }
    const auth = getAuth();
    if(!auth){
      return { ok:false, reason:'setup-required' };
    }
    const ok = await verifyPassword(password, auth) && email === auth.email;
    if(ok){
      resetLockout();
      setSession({ token: createToken(), email, createdAt: Date.now(), expiresAt: Date.now() + 30*60*1000, lastActivity: Date.now() });
      return { ok:true };
    } else {
      recordFailure();
      return { ok:false, reason:'invalid' };
    }
  }

  async function setupAdmin(email, password){
    const strong = typeof password === 'string' && password.length >= 8 && /[A-Za-z]/.test(password) && /\d/.test(password);
    if(!strong){ return { ok:false, reason:'weak' }; }
    const hp = await hashPassword(password);
    setAuth({ email, ...hp, createdAt: Date.now(), version:1 });
    resetLockout();
    return { ok:true };
  }

  function logout(){ clearSession(); }

  // ------------------ Data accessors ------------------
  // Products via Supabase
  async function fetchProducts(){
    try{
      const { data, error } = await supabase.from('products').select('*').order('created_at', { ascending:false });
      if(error) throw error;
      return data || [];
    } catch(err){ console.error('fetchProducts error:', err); showSnack('Failed to fetch products'); return []; }
  }
  async function createProduct(product){
    try{
      console.log('createProduct called with:', product);
      const response = await fetch('/.netlify/functions/addProduct', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(product)
      });
      const result = await response.json();
      if(!response.ok) {
        console.error('createProduct response error:', result);
        throw new Error(result.error || 'Failed to add product');
      }
      showSnack(result.message || 'Product added');
      return true;
    } catch(err){
      console.error('createProduct error:', err);
      showSnack('Failed to add product: ' + err.message);
      return false;
    }
  }
  async function updateProduct(productId, updates){
    try{
      console.log('updateProduct called with:', productId, updates);
      const response = await fetch('/.netlify/functions/updateProduct', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: productId, ...updates })
      });
      const result = await response.json();
      if(!response.ok) {
        console.error('updateProduct response error:', result);
        throw new Error(result.error || 'Failed to update product');
      }
      showSnack(result.message || 'Product updated');
      return true;
    } catch(err){
      console.error('updateProduct error:', err);
      showSnack('Failed to update product: ' + err.message);
      return false;
    }
  }
  async function deleteProductById(productId){
    try{
      const { error } = await supabase.from('products').delete().eq('id', productId);
      if(error) throw error;
      showSnack('Product deleted');
      return true;
    } catch(err){ console.error('deleteProduct error:', err); showSnack('Failed to delete product'); return false; }
  }
  const getOrders = () => ls.get('orders', []);
  const setOrders = (v) => ls.set('orders', v);
  const getUsers = () => ls.get('users', []);
  const setUsers = (v) => ls.set('users', v);
  const getConfig = () => ls.get('appConfig', { logo:'', tagline:'', whatsappNumber:'' });
  const setConfig = (v) => ls.set('appConfig', v);

  function setHeaderBranding(){
    const cfg = getConfig();
    const logo = qs('#site-logo');
    const center = qs('#center-logo');
    const tagline = qs('#site-tagline');
    if(logo){ if(cfg.logo){ logo.src = cfg.logo; logo.style.display='inline-block'; } }
    if(center){ if(cfg.logo){ center.src = cfg.logo; center.style.display='block'; } }
    if(tagline){ tagline.textContent = cfg.tagline || ''; }
  }

  // ------------------ Login screen ------------------
  function wireLogin(){
    const loginBtn = qs('#admin-login-btn');
    const emailEl = qs('#admin-email');
    const passEl = qs('#admin-pass');
    const fillBtn = qs('#fill-demo-btn');

    if(fillBtn){ fillBtn.style.display = 'none'; }

    const title = document.querySelector('.login-card .mdl-card__title-text');

    const authExists = hasAuth();
    if(title){ title.textContent = authExists ? 'Admin Login' : 'Admin Setup'; }
    if(loginBtn){ loginBtn.textContent = authExists ? 'Login' : 'Set Up'; }

    if(loginBtn){
      loginBtn.addEventListener('click', async ()=>{
        const email = (emailEl?.value||'').trim();
        const pass = (passEl?.value||'').trim();
        if(!email || !pass){ showSnack('Enter email and password'); return; }

        loginBtn.disabled = true;
        loginBtn.classList.add('loading');
        loginBtn.setAttribute('aria-busy','true');
        try {
          if(!hasAuth()){
            const res = await setupAdmin(email, pass);
            if(!res.ok){
              if(res.reason==='weak') showSnack('Password must be at least 8 chars with letters and numbers');
              else showSnack('Setup failed');
              return;
            }
            showSnack('Admin account created. Logged in.');
            const s = await login(email, pass);
            if(s.ok){ showDashboard(); } else { showSnack('Unexpected login issue after setup'); }
          } else {
            const res = await login(email, pass);
            if(res.ok){ showSnack('Logged in'); showDashboard(); }
            else if(res.reason==='locked'){ const st = getLockout(); const ms = (st.lockUntil||0) - Date.now(); showSnack(`Too many attempts. Try again in ${Math.ceil(ms/1000)}s`); }
            else if(res.reason==='invalid'){ showSnack('Invalid credentials'); }
            else if(res.reason==='setup-required'){ showSnack('Setup required'); }
          }
        } finally {
          loginBtn.disabled = false;
          loginBtn.classList.remove('loading');
          loginBtn.removeAttribute('aria-busy');
        }
      });
    }
  }

  function showLogin(){
    const loginScreen = qs('#admin-login');
    const dash = qs('#admin-dashboard');
    if(loginScreen){
      loginScreen.style.display = 'flex';
      loginScreen.style.pointerEvents = 'auto';
      loginScreen.setAttribute('aria-hidden','false');
    }
    if(dash) dash.style.display = 'none';
    wireLogin();
    upgrade();
  }

  // ------------------ Dashboard ------------------
  function setupNav(){
    qsa('.bottom-nav .nav-item').forEach(btn=>{
      btn.addEventListener('click', ()=>{
        const view = btn.dataset.view;
        qsa('.view').forEach(v=>v.classList.remove('active'));
        const target = qs('#'+view);
        if(target) target.classList.add('active');
        qsa('.bottom-nav .nav-item').forEach(b=>b.classList.remove('active'));
        btn.classList.add('active');
        if(view==='users-view') renderUsers();
        if(view==='orders-view') renderOrders();
        if(view==='search-view') renderAdminSearchResults();
        upgrade();
      });
    });
  }

  function showDashboard(){
    const loginScreen = qs('#admin-login');
    const dash = qs('#admin-dashboard');
    if(loginScreen){
      loginScreen.style.display = 'none';
      loginScreen.style.pointerEvents = 'none';
      loginScreen.setAttribute('aria-hidden','true');
    }
    if(dash) dash.style.display = 'block';

    setupSessionKeepAlive();

    setHeaderBranding();
    setupNav();

    const logoutBtn = qs('#admin-logout');
    if(logoutBtn){ logoutBtn.addEventListener('click', ()=>{ logout(); location.reload(); }); }

    setupFilters();
    setupProductForm();
    setupConfigForm();
    setupEditModal();
    setupAdminSearch();

    renderUsers();
    renderOrders();
    renderAdminSearchResults();
    upgrade();
  }

  // ------------------ Users ------------------
  function renderUsers(){
    const tbody = qs('#users-table-body');
    if(!tbody) return;
    const users = getUsers();
    const orders = getOrders();
    tbody.innerHTML = '';
    if(users.length===0){
      tbody.innerHTML = '<tr><td class="mdl-data-table__cell--non-numeric" colspan="4">No users yet</td></tr>';
      return;
    }
    users.forEach(u=>{
      const count = orders.filter(o=> (o.user?.phone||'') === (u.phone||'') || (o.user?.email||'') === (u.email||'')).length;
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="mdl-data-table__cell--non-numeric">${u.name||''}</td>
        <td>${u.email||''}</td>
        <td>${u.phone||''}</td>
        <td>${count}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  // ------------------ Orders ------------------
  function setupFilters(){
    ['filter-pending','filter-completed','filter-text'].forEach(id=>{
      const el = qs('#'+id);
      if(el){ el.addEventListener('input', debounce(renderOrders, 150)); el.addEventListener('change', renderOrders); }
    });
  }

  function renderOrders(){
    const container = qs('#orders-admin-list');
    if(!container) return;
    const orders = getOrders().slice().sort((a,b)=> b.createdAt - a.createdAt);
    const showPending = qs('#filter-pending')?.checked ?? true;
    const showCompleted = qs('#filter-completed')?.checked ?? true;
    const text = (qs('#filter-text')?.value||'').toLowerCase();

    container.innerHTML = '';
    const filtered = orders.filter(o=>{
      const byStatus = (o.status==='pending' && showPending) || (o.status==='completed' && showCompleted);
      const inText = !text || (
        o.productSnapshot.name.toLowerCase().includes(text) ||
        (o.productSnapshot.material||'').toLowerCase().includes(text) ||
        (o.productSnapshot.dimensions||'').toLowerCase().includes(text)
      );
      return byStatus && inText;
    });

    if(filtered.length===0){ container.innerHTML = '<p class="mdl-typography--caption">No orders match filters.</p>'; return; }

    filtered.forEach(o=>{
      const card = document.createElement('div');
      card.className = 'mdl-card mdl-shadow--2dp order-admin-card';
      card.innerHTML = `
        <div class="mdl-grid" style="padding:8px;">
          <div class="mdl-cell mdl-cell--2-col mdl-cell--3-col-tablet mdl-cell--12-col-phone">
            <div class="mdl-card__media">
              <img src="${o.productSnapshot.image || 'https://via.placeholder.com/300x200?text=Statue'}" alt="${o.productSnapshot.name}">
            </div>
          </div>
          <div class="mdl-cell mdl-cell--10-col mdl-cell--9-col-tablet mdl-cell--12-col-phone">
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:8px;">
              <div><strong>${o.productSnapshot.name}</strong></div>
              <div>${currency(o.productSnapshot.price)}</div>
              <div>${o.productSnapshot.material}</div>
              <div>${o.productSnapshot.dimensions}</div>
              <div>Buyer: ${o.user.name} • ${o.user.phone}</div>
              <div>Address: ${o.user.address}</div>
              <div>Placed: ${formatDate(o.createdAt)}</div>
              <div>Status: <span class="status-dot ${o.status==='completed'?'completed':'pending'}"></span> ${o.status}
                <button class="mdl-button mdl-js-button mdl-button--raised toggle-status" data-id="${o.id}">Mark Order Complete</button>
              </div>
            </div>
          </div>
        </div>
      `;
      container.appendChild(card);
    });

    // bind status toggles
    qsa('.toggle-status', container).forEach(btn=>{
      btn.addEventListener('click', ()=>{
        const id = btn.getAttribute('data-id');
        toggleOrderStatus(id);
      });
    });
    upgrade();
  }

  function toggleOrderStatus(orderId){
    const orders = getOrders();
    const idx = orders.findIndex(o=> o.id===orderId);
    if(idx>=0){
      orders[idx].status = orders[idx].status==='completed' ? 'pending' : 'completed';
      setOrders(orders);
      showSnack('Order status updated');
      renderOrders();
    }
  }

  // ------------------ Product CRUD ------------------
  function setupProductForm(){
    const saveBtn = qs('#product-save-btn');
    const resetBtn = qs('#product-reset-btn');
    if(saveBtn) saveBtn.addEventListener('click', saveProductFromForm);
    if(resetBtn) resetBtn.addEventListener('click', resetProductForm);

    // file preview for product image
    const fileWrap = qs('label.custom-file[aria-label="Upload product image"]');
    const fileInput = qs('#product-image-file');
    const preview = fileWrap?.querySelector('.file-preview');
    const label = fileWrap?.querySelector('.file-label');
    if(fileInput && preview && label){
      fileInput.addEventListener('change', ()=>{
        const f = fileInput.files?.[0];
        if(!f){ preview.style.backgroundImage=''; label.textContent='Choose image'; return; }
        label.textContent = f.name;
        const url = URL.createObjectURL(f);
        preview.style.backgroundImage = `url('${url}')`;
      });
    }
  }
  function resetProductForm(){
    const form = qs('#product-form');
    if(form) form.reset();
    const idEl = qs('#product-id'); if(idEl) idEl.value = '';
    upgrade();
  }
  function readFileAsDataURL(file){ return new Promise((resolve,reject)=>{ const fr = new FileReader(); fr.onload=()=>resolve(fr.result); fr.onerror=reject; fr.readAsDataURL(file); }); }
  async function saveProductFromForm(){
    const id = (qs('#product-id')?.value||'').trim();
    const name = (qs('#product-name')?.value||'').trim();
    const price = parseFloat(qs('#product-price')?.value||'0');
    const desc = (qs('#product-desc')?.value||'').trim();
    const material = (qs('#product-material')?.value||'').trim();
    const dimensions = (qs('#product-dimensions')?.value||'').trim();
    const categoriesStr = (qs('#product-categories')?.value||'').trim();
    const imageUrl = (qs('#product-image-url')?.value||'').trim();
    const imageFile = qs('#product-image-file')?.files?.[0];

    if(!name || !desc || !(price>0) || !material || !dimensions){ showSnack('Please fill all required fields'); return; }

    let image = imageUrl || '';
    if(!image && imageFile){ image = await readFileAsDataURL(imageFile); }
    const categories = categoriesStr ? categoriesStr.split(',').map(s=>s.trim()).filter(Boolean) : [];

    const saveBtn = qs('#product-save-btn');
    if(saveBtn){ saveBtn.disabled = true; saveBtn.classList.add('loading'); }

    let ok = false;
    if(id){
      ok = await updateProduct(id, { name, price, description: desc, material, dimensions, categories, image });
    } else {
      ok = await createProduct({ name, price, description: desc, material, dimensions, categories, image });
    }

    if(saveBtn){ saveBtn.disabled = false; saveBtn.classList.remove('loading'); }

    if(ok){
      resetProductForm();
      await renderAdminSearchResults();
    }
  }

  // ------------------ Edit modal ------------------
  function setupEditModal(){
    const closeBtn = qs('#edit-modal-close');
    const saveBtn = qs('#edit-save-btn');
    if(closeBtn) closeBtn.addEventListener('click', ()=> showEditModal(false));
    if(saveBtn) saveBtn.addEventListener('click', saveEditModal);
    document.addEventListener('keydown', (e)=>{ if(e.key==='Escape') showEditModal(false); });
  }

  // Focus trap for modal
  let lastFocus = null;
  function trapFocus(container){
    lastFocus = document.activeElement;
    const selectors = 'a[href], button, textarea, input, select, [tabindex]:not([tabindex="-1"])';
    const nodes = Array.from(container.querySelectorAll(selectors)).filter(el=> !el.hasAttribute('disabled'));
    if(nodes.length){ nodes[0].focus(); }
    function loop(e){
      if(e.key !== 'Tab') return;
      const first = nodes[0];
      const last = nodes[nodes.length - 1];
      if(e.shiftKey && document.activeElement === first){ e.preventDefault(); last.focus(); }
      else if(!e.shiftKey && document.activeElement === last){ e.preventDefault(); first.focus(); }
    }
    container.addEventListener('keydown', loop);
    container._focusLoop = loop;
  }
  function releaseFocus(){
    const modal = qs('#edit-modal');
    if(modal && modal._focusLoop){ modal.removeEventListener('keydown', modal._focusLoop); modal._focusLoop = null; }
    if(lastFocus){ try{ lastFocus.focus(); }catch(_){} lastFocus = null; }
  }
  function showEditModal(show){
    const modal = qs('#edit-modal');
    if(modal){
      modal.classList.toggle('show', !!show);
      modal.setAttribute('aria-hidden', show? 'false':'true');
      if(show){ trapFocus(modal); } else { releaseFocus(); }
    }
  }
  function openEditModal(product){
    if(!product) return;
    const setters = [
      ['#edit-id','value', product.id],
      ['#edit-name','value', product.name||''],
      ['#edit-price','value', product.price||''],
      ['#edit-desc','value', product.description||''],
      ['#edit-material','value', product.material||''],
      ['#edit-dimensions','value', product.dimensions||''],
      ['#edit-categories','value', (product.categories||[]).join(', ')],
      ['#edit-image-url','value', product.image||''],
    ];
    setters.forEach(([sel, prop, val])=>{ const el = qs(sel); if(el) el[prop] = val; });
    showEditModal(true);
    upgrade();
  }
  async function saveEditModal(){
    const id = (qs('#edit-id')?.value||'').trim();
    const name = (qs('#edit-name')?.value||'').trim();
    const price = parseFloat(qs('#edit-price')?.value||'0');
    const desc = (qs('#edit-desc')?.value||'').trim();
    const material = (qs('#edit-material')?.value||'').trim();
    const dimensions = (qs('#edit-dimensions')?.value||'').trim();
    const categoriesStr = (qs('#edit-categories')?.value||'').trim();
    const imageUrl = (qs('#edit-image-url')?.value||'').trim();
    const imageFile = qs('#edit-image-file')?.files?.[0];

    if(!id){ showSnack('No product selected'); return; }
    if(!name || !desc || !(price>0) || !material || !dimensions){ showSnack('Please fill all required fields'); return; }

    let image = imageUrl || '';
    if(!image && imageFile){ image = await readFileAsDataURL(imageFile); }
    const categories = categoriesStr ? categoriesStr.split(',').map(s=>s.trim()).filter(Boolean) : [];

    const saveBtn = qs('#edit-save-btn');
    if(saveBtn){ saveBtn.disabled = true; saveBtn.classList.add('loading'); }

    const ok = await updateProduct(id, { name, price, description: desc, material, dimensions, categories, image });

    if(saveBtn){ saveBtn.disabled = false; saveBtn.classList.remove('loading'); }

    if(ok){
      showSnack('Product updated');
      showEditModal(false);
      await renderAdminSearchResults();
    }
  }

  // ------------------ Admin product search ------------------
  function setupAdminSearch(){ const input = qs('#admin-search-input'); if(input){ input.addEventListener('input', debounce(renderAdminSearchResults, 250)); } }
  async function renderAdminSearchResults(){
    const input = qs('#admin-search-input');
    const q = (input?.value||'').toLowerCase().trim();
    const results = qs('#admin-search-results');
    const count = qs('#admin-search-count');
    if(!results || !count) return;

    results.innerHTML = '<div class="mdl-typography--caption">Loading products…</div>';
    const products = await fetchProducts();

    const filtered = !q ? products : products.filter(p =>
      (p.name||'').toLowerCase().includes(q) || (p.description||'').toLowerCase().includes(q) || (p.material||'').toLowerCase().includes(q) || (Array.isArray(p.categories)? p.categories: String(p.categories||'').split(',')).some(c=> String(c).toLowerCase().includes(q))
    );

    count.textContent = `${filtered.length} result(s)`;
    results.innerHTML = '';

    filtered.forEach(p=>{
      const cell = document.createElement('div');
      cell.className = 'mdl-cell mdl-cell--6-col mdl-cell--4-col-tablet mdl-cell--3-col-desktop';
      cell.innerHTML = `
        <div class="mdl-card mdl-shadow--2dp product-card">
          <div class="mdl-card__media" style="height:160px; display:flex; align-items:center; justify-content:center; background:#fafafa;">
            <img src="${p.image || 'https://via.placeholder.com/400x300?text=Statue'}" alt="${p.name||''}" style="max-height:100%;max-width:100%;object-fit:cover;">
          </div>
          <div class="mdl-card__title">
            <h2 class="mdl-card__title-text">${p.name||''}</h2>
          </div>
          <div class="mdl-card__supporting-text">
            <div>${currency(p.price)} • ${p.material||''} • ${p.dimensions||''}</div>
            <div class="mdl-typography--caption">${Array.isArray(p.categories)? p.categories.join(', '): (p.categories||'')}</div>
          </div>
          <div class="mdl-card__actions mdl-card--border" style="display:flex; gap:8px;">
            <button class="mdl-button mdl-js-button mdl-button--raised" data-edit="${p.id}">Edit</button>
            <button class="mdl-button mdl-js-button" data-delete="${p.id}">Delete</button>
          </div>
        </div>
      `;
      results.appendChild(cell);
    });

    qsa('[data-edit]', results).forEach(btn=>{
      btn.addEventListener('click', async ()=>{
        const id = btn.getAttribute('data-edit');
        const list = await fetchProducts();
        const product = list.find(p=> String(p.id)===String(id));
        if(product) openEditModal(product);
      });
    });
    qsa('[data-delete]', results).forEach(btn=>{
      btn.addEventListener('click', async ()=>{
        const id = btn.getAttribute('data-delete');
        if(!confirm('Delete this product? Orders will keep snapshots.')) return;
        btn.disabled = true;
        const ok = await deleteProductById(id);
        btn.disabled = false;
        if(ok) renderAdminSearchResults();
      });
    });
    upgrade();
  }

  function deleteProduct(id){
    // legacy hook retained for safety; new UI uses deleteProductById directly
    (async ()=>{
      if(!confirm('Delete this product? Orders will keep snapshots.')) return;
      await deleteProductById(id);
      renderAdminSearchResults();
    })();
  }

  // ------------------ Branding / Settings ------------------
  function setupConfigForm(){
    const cfg = getConfig();
    const taglineEl = qs('#config-tagline');
    const waEl = qs('#config-whatsapp');
    const fileEl = qs('#config-logo-file');
    if(taglineEl) taglineEl.value = cfg.tagline || '';
    if(waEl) waEl.value = cfg.whatsappNumber || '';

    // file preview for logo
    const fileWrap = qs('label.custom-file[aria-label="Upload logo"]');
    const preview = fileWrap?.querySelector('.file-preview');
    const label = fileWrap?.querySelector('.file-label');
    if(fileEl && preview && label){
      fileEl.addEventListener('change', ()=>{
        const f = fileEl.files?.[0];
        if(!f){ preview.style.backgroundImage=''; label.textContent='Choose image'; return; }
        label.textContent = f.name;
        const url = URL.createObjectURL(f);
        preview.style.backgroundImage = `url('${url}')`;
      });
    }

    const saveBtn = qs('#config-save-btn');
    if(saveBtn){
      saveBtn.addEventListener('click', async ()=>{
        const tagline = (taglineEl?.value||'').trim();
        const whatsappNumber = (waEl?.value||'').trim();
        let logo = cfg.logo || '';
        if(fileEl && fileEl.files && fileEl.files[0]){ logo = await readFileAsDataURL(fileEl.files[0]); }
        const newCfg = { ...cfg, tagline, whatsappNumber, logo };
        setConfig(newCfg);
        setHeaderBranding();
        showSnack('Settings saved');
      });
    }
  }

  // ------------------ Init ------------------
  function init(){
    seedIfNeeded();
    if(isLoggedIn()) showDashboard(); else showLogin();
  }

  document.addEventListener('DOMContentLoaded', init);
})();
