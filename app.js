(function(){
  'use strict';

  // ------------------ Utilities ------------------
  const ls = {
    get(key, fallback){
      try{ const v = JSON.parse(localStorage.getItem(key)); return v ?? fallback; }catch(e){ return fallback; }
    },
    set(key, value){ localStorage.setItem(key, JSON.stringify(value)); }
  };
  const generateId = (prefix='id') => `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2,6)}`;
  const currency = (n) => new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR' }).format(Number(n)||0);
  const formatDate = (ts) => new Date(ts).toLocaleString();
  const debounce = (fn, delay=250) => { let t; return (...args) => { clearTimeout(t); t=setTimeout(()=>fn(...args), delay); }; };

  // ------------------ Auth (client-side) ------------------
  const USER_DB_KEY = 'usersDB';
  const USER_SESSION_KEY = 'userSession';

  const enc = new TextEncoder();
  const toBytes = (s) => enc.encode(s);
  const toB64 = (arrBuf) => btoa(String.fromCharCode(...new Uint8Array(arrBuf)));
  const fromB64 = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));

  async function pbkdf2(password, saltBytes, iterations = 120000){
    const keyMaterial = await crypto.subtle.importKey('raw', toBytes(password), { name:'PBKDF2' }, false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name:'PBKDF2', salt: saltBytes, iterations, hash:'SHA-256' },
      keyMaterial,
      { name:'AES-GCM', length: 256 },
      true,
      ['encrypt','decrypt']
    );
    const raw = await crypto.subtle.exportKey('raw', key);
    return toB64(raw);
  }
  function getUsersDB(){ return ls.get(USER_DB_KEY, []); }
  function setUsersDB(db){ ls.set(USER_DB_KEY, db); }

  async function signupUser({ name, email, phone, address, password }){
    const db = getUsersDB();
    if(db.some(u=> u.email.toLowerCase() === email.toLowerCase())) return { ok:false, reason:'exists' };
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const hash = await pbkdf2(password, salt);
    const user = { id: generateId('user'), name, email, phone, address, pass:{ salt: toB64(salt), iterations:120000, hash } };
    db.push(user); setUsersDB(db);
    // Set profile for convenience
    saveProfile({ name, email, phone, address, notes:'' });
    upsertAdminUsers(name, email, phone, address);
    setUserSession({ uid: user.id, email: user.email, createdAt: Date.now(), expiresAt: Date.now()+ 30*60*1000 });
    return { ok:true, user };
  }

  async function loginUser(email, password){
    const db = getUsersDB();
    const user = db.find(u=> u.email.toLowerCase()===email.toLowerCase());
    if(!user) return { ok:false };
    const salt = fromB64(user.pass.salt);
    const calc = await pbkdf2(password, salt, user.pass.iterations||120000);
    if(calc !== user.pass.hash) return { ok:false };
    setUserSession({ uid: user.id, email: user.email, createdAt: Date.now(), expiresAt: Date.now()+ 30*60*1000 });
    // Always sync profile to the logged-in user
    saveProfile({ name: user.name, email: user.email, phone: user.phone, address: user.address, notes: getProfile()?.notes || '' });
    upsertAdminUsers(user.name, user.email, user.phone, user.address);
    return { ok:true, user };
  }

  function getUserSession(){ return ls.get(USER_SESSION_KEY, null); }
  function setUserSession(v){ ls.set(USER_SESSION_KEY, v); }
  function clearUserSession(){ localStorage.removeItem(USER_SESSION_KEY); }
  function isUserLoggedIn(){ const s = getUserSession(); return !!(s && s.expiresAt > Date.now()); }
  function refreshUserSession(){ const s = getUserSession(); if(!s) return; setUserSession({ ...s, expiresAt: Date.now()+ 30*60*1000 }); }
  function setupUserSessionKeepAlive(){
    const handler = debounce(refreshUserSession, 60000);
    ['click','keydown','mousemove','scroll','touchstart'].forEach(evt => window.addEventListener(evt, handler, { passive:true }));
  }

  function showAuthModal(show){
    console.log('showAuthModal called with:', show);
    const modal = qs('#auth-modal');
    if(!modal) return;
    modal.classList.toggle('show', !!show);
    modal.setAttribute('aria-hidden', show? 'false':'true');
  }
  function wireAuthModal(){
    const tabLogin = qs('#auth-tab-login');
    const tabSignup = qs('#auth-tab-signup');
    const loginForm = qs('#auth-login-form');
    const signupForm = qs('#auth-signup-form');
    const loginBtn = qs('#auth-login-btn');
    const signupBtn = qs('#auth-signup-btn');

    if(tabLogin && tabSignup){
      tabLogin.addEventListener('click', ()=>{
        tabLogin.classList.add('active'); tabSignup.classList.remove('active');
        loginForm.style.display='block'; signupForm.style.display='none';
        loginBtn.style.display='inline-flex'; signupBtn.style.display='none';
      });
      tabSignup.addEventListener('click', ()=>{
        tabSignup.classList.add('active'); tabLogin.classList.remove('active');
        signupForm.style.display='block'; loginForm.style.display='none';
        signupBtn.style.display='inline-flex'; loginBtn.style.display='none';
      });
    }

    if(loginBtn){
      loginBtn.addEventListener('click', async ()=>{
        const email = (qs('#auth-login-email').value||'').trim();
        const pass = (qs('#auth-login-pass').value||'').trim();
        if(!email || !pass){ showSnack('Enter email and password'); return; }
        loginBtn.disabled = true;
        const res = await loginUser(email, pass);
        loginBtn.disabled = false;
        if(res.ok){ showSnack('Welcome back'); showAuthModal(false); if(authTimer) clearTimeout(authTimer); loadProfileIntoForm(); renderOrders(); setupUserSessionKeepAlive(); }
        else { showSnack('Invalid credentials'); }
      });
    }

    if(signupBtn){
      signupBtn.addEventListener('click', async ()=>{
        const name = (qs('#auth-name').value||'').trim();
        const email = (qs('#auth-email').value||'').trim();
        const phone = (qs('#auth-phone').value||'').trim();
        const address = (qs('#auth-address').value||'').trim();
        const pass = (qs('#auth-pass').value||'').trim();
        const pass2 = (qs('#auth-pass2').value||'').trim();
        if(!name || !email || !phone || !address || !pass || !pass2){ showSnack('Please fill all fields'); return; }
        if(pass.length < 8){ showSnack('Password must be at least 8 characters'); return; }
        if(pass !== pass2){ showSnack('Passwords do not match'); return; }
        signupBtn.disabled = true;
        const res = await signupUser({ name, email, phone, address, password: pass });
        signupBtn.disabled = false;
        if(res.ok){ showSnack('Account created'); showAuthModal(false); loadProfileIntoForm(); renderOrders(); setupUserSessionKeepAlive(); }
        else if(res.reason==='exists') { showSnack('Account already exists'); }
        else { showSnack('Sign up failed'); }
      });
    }
  }

  let authTimer = null;

  function requireAuthOnFirstVisit(){
    console.log('requireAuthOnFirstVisit called, logged in:', isUserLoggedIn());
    if(!isUserLoggedIn()){
      authTimer = setTimeout(() => {
        console.log('Auth timer triggered, showing modal');
        showAuthModal(true);
      }, 5000); // 5 seconds delay for testing
    } else {
      setupUserSessionKeepAlive();
    }
  }

  // ------------------ Seeds ------------------
  function seedIfNeeded(){
    if(!ls.get('appConfig')){
      ls.set('appConfig', {
        logo: '',
        tagline: 'Handcrafted Stone & Marble Statues',
        whatsappNumber: '+919999999999',
        version: 1
      });
    }
    if(!ls.get('profile')){
      ls.set('profile', {
        name: 'Default User',
        email: 'user@example.com',
        phone: '+91 9999999999',
        address: 'Your City, State, Country',
        notes: ''
      });
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
      ].map(p=>({
        id: generateId('prod'),
        description: `${p.name} handcrafted in ${p.material}.` ,
        ...p
      }));
      ls.set('products', seed);
    }
    if(!ls.get('orders')){ ls.set('orders', []); }
    if(!ls.get('users')){ ls.set('users', []); }
  }

  // ------------------ DOM Helpers ------------------
  const qs = (sel, el=document) => el.querySelector(sel);
  const qsa = (sel, el=document) => Array.from(el.querySelectorAll(sel));
  function showSnack(msg){
    const container = qs('#snackbar');
    container.MaterialSnackbar.showSnackbar({ message: msg });
  }
  function setHeaderBranding(){
    const cfg = ls.get('appConfig', {});
    const logo = qs('#site-logo');
    const heroLogo = qs('#hero-logo');
    const tagline = qs('#site-tagline');
    if(cfg.logo){
      if(logo){ logo.src = cfg.logo; logo.style.display = 'inline-block'; }
      if(heroLogo){ heroLogo.src = cfg.logo; }
    }
    if(cfg.tagline && tagline){ tagline.textContent = cfg.tagline; }
  }

  // ------------------ Navigation ------------------
  function setupNav(){
    qsa('.bottom-nav .nav-item').forEach(btn=>{
      btn.addEventListener('click', ()=>{
        const view = btn.dataset.view;
        qsa('.view').forEach(v=>v.classList.remove('active'));
        qs(`#${view}`).classList.add('active');
        qsa('.bottom-nav .nav-item').forEach(b=>b.classList.remove('active'));
        btn.classList.add('active');
      });
    });
  }

  // ------------------ Products Rendering ------------------
  function buildProductCard(p){
    const cfg = ls.get('appConfig', {});
    const waNumber = cfg.whatsappNumber || '';
    const waText = encodeURIComponent(`Hello, I’m interested in ${p.name} priced at ${currency(p.price)}. Material: ${p.material}, Dimensions: ${p.dimensions}.`);
    const waLink = `https://wa.me/${waNumber.replace(/\D/g,'')}?text=${waText}`;

    const cell = document.createElement('div');
    cell.className = 'mdl-cell mdl-cell--6-col mdl-cell--4-col-tablet mdl-cell--3-col-desktop';

    cell.innerHTML = `
      <div class="mdl-card mdl-shadow--2dp product-card">
        <div class="mdl-card__media">
          <span class="price-badge">${currency(p.price)}</span>
          <span class="material-chip">${p.material}</span>
          <img src="${p.image || 'https://via.placeholder.com/800x600?text=Statue'}" alt="${p.name}">
        </div>
        <div class="mdl-card__title">
          <h2 class="mdl-card__title-text">${p.name}</h2>
        </div>
        <div class="mdl-card__supporting-text">
          <div class="product-meta">
            <span>${p.dimensions}</span>
            <span>${(p.categories||[]).join(', ')}</span>
          </div>
        </div>
        <div class="mdl-card__actions mdl-card--border product-actions">
          <button class="mdl-button mdl-js-button mdl-button--raised mdl-button--colored" data-order="${p.id}">Order</button>
          <a href="${waLink}" target="_blank" rel="noopener" class="mdl-button mdl-js-button">WhatsApp</a>
        </div>
      </div>
    `;

    // Attach event after insert
    setTimeout(()=>{
      const btn = cell.querySelector(`[data-order="${p.id}"]`);
      btn && btn.addEventListener('click', ()=> openOrderForm(p.id));
    });

    return cell;
  }
  function renderProducts(list, container){
    container.innerHTML='';
    const frag = document.createDocumentFragment();
    list.forEach(p=> frag.appendChild(buildProductCard(p)));
    container.appendChild(frag);
  }
  function loadProducts(){ return ls.get('products', []); }

  // Category chips
  function renderCategoryChips(products){
    const set = new Set();
    products.forEach(p=> (p.categories||[]).forEach(c=> set.add(c)));
    const chips = qs('#category-chips');
    chips.innerHTML='';
    const allChip = document.createElement('button');
    allChip.className='chip active';
    allChip.textContent='All';
    allChip.addEventListener('click', ()=>{
      qsa('#category-chips .chip').forEach(c=>c.classList.remove('active'));
      allChip.classList.add('active');
      renderProducts(loadProducts(), qs('#products-grid'));
    });
    chips.appendChild(allChip);

    Array.from(set).sort().forEach(cat=>{
      const b = document.createElement('button');
      b.className='chip'; b.textContent=cat;
      b.addEventListener('click', ()=>{
        qsa('#category-chips .chip').forEach(c=>c.classList.remove('active'));
        b.classList.add('active');
        const filtered = loadProducts().filter(p=> (p.categories||[]).some(x=> x.toLowerCase()===cat.toLowerCase()));
        renderProducts(filtered, qs('#products-grid'));
      });
      chips.appendChild(b);
    });
  }

  // ------------------ Search ------------------
  function searchProducts(query){
    const q = (query||'').trim().toLowerCase();
    if(!q) return loadProducts();
    return loadProducts().filter(p=>{
      const inName = p.name.toLowerCase().includes(q);
      const inMaterial = (p.material||'').toLowerCase().includes(q);
      const inCat = (p.categories||[]).some(c=> c.toLowerCase().includes(q));
      return inName || inMaterial || inCat;
    });
  }
  function setupSearch(){
    const input = qs('#search-input');
    const results = qs('#search-results');
    const count = qs('#search-count');
    const doSearch = debounce(()=>{
      const list = searchProducts(input.value);
      count.textContent = `${list.length} result(s)`;
      renderProducts(list, results);
    }, 250);
    input.addEventListener('input', doSearch);
    // initial render
    renderProducts(loadProducts(), results);
    count.textContent = `${loadProducts().length} result(s)`;
  }

  // ------------------ Orders ------------------
  function getOrders(){ return ls.get('orders', []); }
  function getProfile(){ return ls.get('profile', {}); }
  function saveProfile(p){ ls.set('profile', p); }
  // Ensure public user is reflected in admin users list
  function upsertAdminUsers(name, email, phone, address){
    const users = ls.get('users', []);
    const idx = users.findIndex(u=> (u.phone||'') === (phone||'') || (u.email||'') === (email||''));
    const userObj = { id: idx>=0 ? users[idx].id : generateId('user'), name, email, phone, address };
    if(idx>=0) users[idx] = userObj; else users.push(userObj);
    ls.set('users', users);
  }

  function getStatusDot(status){
    const span = document.createElement('span');
    span.className = `status-dot ${status==='completed'?'completed':'pending'}`;
    span.title = status==='completed' ? 'Completed' : 'Pending';
    return span;
  }

  function renderOrders(){
    const container = qs('#orders-list');
    container.innerHTML='';
    const profile = getProfile();
    const session = getUserSession();
    const orders = getOrders();
    let list = [];
    if(session && session.uid){
      list = orders.filter(o => o.userId === session.uid);
    } else {
      list = orders.filter(o=> (o.user?.phone||'') === (profile.phone||'') || (o.user?.email||'') === (profile.email||''));
    }
    if(list.length===0){
      container.innerHTML = '<p class="muted">No orders yet. Place an order from Home.</p>';
      return;
    }
    list.sort((a,b)=> b.createdAt - a.createdAt);
    list.forEach(o=>{
      const card = document.createElement('div');
      card.className = 'mdl-card mdl-shadow--2dp order-card';
      card.innerHTML = `
        <div class="mdl-grid" style="padding: 8px;">
          <div class="mdl-cell mdl-cell--2-col mdl-cell--3-col-tablet mdl-cell--4-col-phone">
            <div class="mdl-card__media">
              <img src="${o.productSnapshot.image || 'https://via.placeholder.com/300x200?text=Statue'}" alt="${o.productSnapshot.name}">
            </div>
          </div>
          <div class="mdl-cell mdl-cell--10-col mdl-cell--9-col-tablet mdl-cell--4-col-phone">
            <div class="order-details">
              <div><strong>${o.productSnapshot.name}</strong></div>
              <div>${currency(o.productSnapshot.price)}</div>
              <div>${o.productSnapshot.material}</div>
              <div>${o.productSnapshot.dimensions}</div>
              <div>Placed: ${formatDate(o.createdAt)}</div>
              <div>Status: <span class="status-dot ${o.status==='completed'?'completed':'pending'}"></span> <span class="muted">${o.status==='completed'?'Order Confirmed':'Pending'}</span></div>
              <div class="mdl-cell--12-col">Ship To: ${o.user.name}, ${o.user.address}, ${o.user.phone}${o.user.notes? ', Notes: '+o.user.notes : ''}</div>
            </div>
          </div>
        </div>
      `;
      container.appendChild(card);
    });
  }

  // ------------------ Order Modal ------------------
  let currentOrderProductId = null;
  function openOrderForm(productId){
    currentOrderProductId = productId;
    const product = loadProducts().find(p=> p.id===productId);
    if(!product) return;

    const prev = qs('#order-product-preview');
    prev.innerHTML = `
      <img src="${product.image || 'https://via.placeholder.com/80?text=Statue'}" alt="${product.name}">
      <div>
        <div><strong>${product.name}</strong></div>
        <div>${currency(product.price)}</div>
        <div>${product.material} • ${product.dimensions}</div>
      </div>
    `;

    // Prefill from profile
    const profile = getProfile();
    qs('#order-name').value = profile.name || '';
    qs('#order-address').value = profile.address || '';
    qs('#order-phone').value = profile.phone || '';
    qs('#order-notes').value = '';

    showModal(true);
  }

  function showModal(show){
    const modal = qs('#order-modal');
    modal.classList.toggle('show', !!show);
    modal.setAttribute('aria-hidden', show? 'false':'true');
    if(show){
      // focus first field
      setTimeout(()=> qs('#order-name').focus(), 100);
    }
  }

  function submitOrder(){
    if(!currentOrderProductId) return;
    const name = qs('#order-name').value.trim();
    const address = qs('#order-address').value.trim();
    const phone = qs('#order-phone').value.trim();
    const notes = qs('#order-notes').value.trim();

    if(!name || !address || !phone){ showSnack('Please fill all required fields'); return; }

    const product = loadProducts().find(p=> p.id===currentOrderProductId);
    if(!product){ showSnack('Product not found'); return; }

    const session = getUserSession();
    const order = {
      id: generateId('ord'),
      userId: session?.uid || null,
      productId: product.id,
      productSnapshot: {
        name: product.name,
        price: product.price,
        image: product.image,
        material: product.material,
        dimensions: product.dimensions
      },
      user: { name, address, phone, email: profile.email||'', notes },
      status: 'pending',
      createdAt: Date.now()
    };

    const orders = getOrders();
    orders.push(order);
    ls.set('orders', orders);

    // Update users list (by phone or email)
    const users = ls.get('users', []);
    const profile = getProfile();
    const existingIdx = users.findIndex(u=> (u.phone||'') === phone || (u.email||'') === (profile.email||''));
    const userObj = { id: existingIdx>=0 ? users[existingIdx].id : generateId('user'), name, email: profile.email||'', phone, address };
    if(existingIdx>=0) users[existingIdx] = userObj; else users.push(userObj);
    ls.set('users', users);

    showModal(false);
    showSnack('Order placed successfully');
    renderOrders();

    // switch to orders tab
    qsa('.bottom-nav .nav-item').forEach(b=> b.classList.remove('active'));
    qs('.bottom-nav [data-view="orders-view"]').classList.add('active');
    qsa('.view').forEach(v=> v.classList.remove('active'));
    qs('#orders-view').classList.add('active');
  }

  // ------------------ Profile ------------------
  function loadProfileIntoForm(){
    const p = getProfile();
    qs('#profile-name').value = p.name || '';
    qs('#profile-email').value = p.email || '';
    qs('#profile-phone').value = p.phone || '';
    qs('#profile-address').value = p.address || '';
    qs('#profile-notes').value = p.notes || '';
    const btn = qs('#save-profile-btn');
    if(btn){ btn.textContent = (p && (p.name||p.email||p.phone||p.address)) ? 'Update Profile' : 'Save Profile'; }
    updateProfileCompleteness();
  }

  function validateEmail(v){ return /.+@.+\..+/.test(v); }
  function validatePhone(v){ return /^\+?\d[\d\s-]{9,14}$/.test(v); }
  function updateProfileCompleteness(){
    const name = qs('#profile-name').value.trim();
    const email = qs('#profile-email').value.trim();
    const phone = qs('#profile-phone').value.trim();
    const address = qs('#profile-address').value.trim();
    const valid = !!(name && validateEmail(email) && validatePhone(phone) && address);
    qs('#profile-completeness').textContent = valid ? 'Profile complete' : 'Please complete required fields (Name, Email, Phone, Address).';
  }
  function setupProfileForm(){
    ['#profile-name','#profile-email','#profile-phone','#profile-address'].forEach(sel=>{
      qs(sel).addEventListener('input', updateProfileCompleteness);
    });
    qs('#save-profile-btn').addEventListener('click', ()=>{
      const name = qs('#profile-name').value.trim();
      const email = qs('#profile-email').value.trim();
      const phone = qs('#profile-phone').value.trim();
      const address = qs('#profile-address').value.trim();
      const notes = qs('#profile-notes').value.trim();
      if(!name || !validateEmail(email) || !validatePhone(phone) || !address){
        showSnack('Please provide valid Name, Email, Phone and Address');
        return;
      }
      saveProfile({ name, email, phone, address, notes });
      upsertAdminUsers(name, email, phone, address);
      showSnack('Profile saved');
      renderOrders();
    });
  }

  // ------------------ Init ------------------
  function init(){
    seedIfNeeded();
    setHeaderBranding();
    setupNav();
    wireAuthModal();
    requireAuthOnFirstVisit();

    const products = loadProducts();
    renderProducts(products, qs('#products-grid'));
    renderCategoryChips(products);

    setupSearch();

    setupProfileForm();
    loadProfileIntoForm();

    renderOrders();

    // modal
    qs('#order-modal-close').addEventListener('click', ()=> showModal(false));
    qs('#submit-order-btn').addEventListener('click', submitOrder);
    document.addEventListener('keydown', (e)=>{ if(e.key==='Escape') showModal(false); });
  }

  document.addEventListener('DOMContentLoaded', init);
})();
