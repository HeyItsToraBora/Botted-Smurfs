// --- Notification System ---
function showNotification(msg, type = 'info', duration = 3000) {
    const notif = document.getElementById('notification');
    notif.textContent = msg;
    notif.className = 'notification show ' + type;
    setTimeout(() => notif.className = 'notification', duration);
}

// --- Fetch and Render Purchases ---
async function fetchPurchases() {
    try {
        const res = await fetch('/my-purchases', {
            headers: {
                'Authorization': 'Bearer ' + localStorage.getItem('accessToken')
            }
        });
        const data = await res.json();
        if (!data.success) throw new Error(data.message || 'Failed to load purchases');
        renderPurchasesTable(data.purchases);
    } catch (e) {
        showNotification('Error loading purchases: ' + e.message, 'error');
    }
}

function renderPurchasesTable(purchases) {
    const tbody = document.querySelector('#purchasesTable tbody');
    tbody.innerHTML = '';
    if (!purchases.length) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;opacity:0.7;">No purchases found.</td></tr>';
        return;
    }
    for (const p of purchases) {
        const paidStatus = p.payment_confirmation === 'confirmed'
            ? '<span class="status paid" style="background:#4caf5033;color:#4caf50;">Paid</span>'
            : '<span class="status not-paid" style="background:#ffb34733;color:#ffb347;">Not Paid</span>';
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>#${p.id}</td>
            <td>${p.gmail_to_be_sent ? `<span style='font-family:monospace;'>${p.gmail_to_be_sent}</span>` : '-'}</td>
            <td>${p.subtotal_after_coupon.toFixed(2)}$</td>
            <td><span class="status ${p.status}">${p.status.charAt(0).toUpperCase() + p.status.slice(1)}</span></td>
            <td>${paidStatus}</td>
            <td>${new Date(p.created_at).toLocaleString()}</td>
            <td>
                <button class="btn btn-details" data-id="${p.id}">Details</button>
                ${(p.status === 'pending' && p.payment_confirmation !== 'confirmed') ? `<button class="btn btn-mark-paid" data-id="${p.id}">Mark as Paid</button>` : ''}
            </td>
        `;
        tbody.appendChild(tr);
    }
    // Add event listeners
    tbody.querySelectorAll('.btn-details').forEach(btn => {
        btn.addEventListener('click', function() {
            openPurchaseDetailsModal(this.dataset.id, purchases);
        });
    });
    tbody.querySelectorAll('.btn-mark-paid').forEach(btn => {
        btn.addEventListener('click', function() {
            markAsPaid(this.dataset.id);
        });
    });
}

// --- Purchase Details Modal ---
function openPurchaseDetailsModal(purchaseId, purchases) {
    const p = purchases.find(p => p.id == purchaseId);
    if (!p) return;
    let html = '';
    html += `<ul class='modal-details-list'>`;
    html += `<li><b>Order Number:</b> #${p.id}</li>`;
    html += `<li><b>Date:</b> ${new Date(p.created_at).toLocaleString()}</li>`;
    html += `<li><b>Status:</b> <span class='status ${p.status}'>${p.status.charAt(0).toUpperCase() + p.status.slice(1)}</span></li>`;
    html += `<li><b>Paid:</b> ` + (p.payment_confirmation === 'confirmed'
        ? `<span class='status paid' style='background:#4caf5033;color:#4caf50;'>Paid</span>`
        : `<span class='status not-paid' style='background:#ffb34733;color:#ffb347;'>Not Paid</span>`) + `</li>`;
    html += `<li><b>Payment Currency:</b> ${p.payment_currency || '$'}</li>`;
    html += `<li><b>Total Before Coupon:</b> ${(p.total_before_coupon).toFixed(2)}$</li>`;
    if (p.coupon_code) {
        html += `<li><b>Coupon:</b> ${p.coupon_code} (${p.coupon_percent}%)</li>`;
        html += `<li><b>Discount:</b> -${(p.total_before_coupon - p.subtotal_after_coupon).toFixed(2)}$</li>`;
    }
    html += `<li><b>Total Paid:</b> ${p.subtotal_after_coupon.toFixed(2)}$</li>`;
    if (p.gmail_to_be_sent) {
        html += `<li><b>Gmail to be Sent:</b> <span style='font-family:monospace;'>${p.gmail_to_be_sent}</span></li>`;
    }
    html += `<li><b>Payment Method(s):</b> <ul style='margin:0.3em 0 0 1.2em;'>`;
    for (const net of p.payment_networks) {
        html += `<li><b>${net.network}:</b> <span style='word-break:break-all;font-family:monospace;'>${net.address}</span></li>`;
    }
    html += `</ul></li>`;
    html += `<li><b>Items:</b></li>`;
    html += `<li><table style='width:100%;margin-top:0.5em;background:#20263a;border-radius:6px;'><thead><tr><th style='color:#7abaff;text-align:left;padding:0.3em 0.5em;'>Name</th><th style='color:#7abaff;text-align:left;padding:0.3em 0.5em;'>Server</th><th style='color:#7abaff;text-align:right;padding:0.3em 0.5em;'>Qty</th><th style='color:#7abaff;text-align:right;padding:0.3em 0.5em;'>Price</th><th style='color:#7abaff;text-align:right;padding:0.3em 0.5em;'>Total</th></tr></thead><tbody>`;
    for (const item of p.items) {
        html += `<tr><td style='padding:0.3em 0.5em;'>${item.offer_name}</td><td style='padding:0.3em 0.5em;'>${item.server_name}</td><td style='padding:0.3em 0.5em;text-align:right;'>${item.quantity}</td><td style='padding:0.3em 0.5em;text-align:right;'>${item.price_per_account.toFixed(2)}$</td><td style='padding:0.3em 0.5em;text-align:right;'>${(item.price_per_account * item.quantity).toFixed(2)}$</td></tr>`;
    }
    html += `</tbody></table></li>`;
    html += `</ul>`;
    document.getElementById('purchaseDetailsContent').innerHTML = html;
    document.getElementById('purchaseDetailsModal').style.display = 'block';
}
document.getElementById('closePurchaseDetailsModal').onclick =
document.getElementById('closePurchaseDetailsBtn').onclick = function() {
    document.getElementById('purchaseDetailsModal').style.display = 'none';
};

// --- Mark as Paid ---
async function markAsPaid(purchaseId) {
    try {
        const res = await fetch(`/purchase/${purchaseId}/confirm-payment`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + localStorage.getItem('accessToken')
            },
            body: JSON.stringify({ payment_confirmation: 'confirmed' })
        });
        const data = await res.json();
        if (data.success) {
            showNotification('Marked as paid! Admin will review your payment.', 'success');
            fetchPurchases();
        } else {
            showNotification(data.message || 'Failed to mark as paid', 'error');
        }
    } catch (e) {
        showNotification('Error: ' + e.message, 'error');
    }
}

// --- Theme Toggle ---
const themeBtn = document.getElementById('themeToggleBtn');
function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    themeBtn.textContent = theme === 'dark' ? '🌙' : '☀️';
}
themeBtn.addEventListener('click', function() {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    setTheme(current === 'dark' ? 'light' : 'dark');
    themeBtn.classList.add('animating');
    setTimeout(() => themeBtn.classList.remove('animating'), 400);
});
// On load
setTheme(localStorage.getItem('theme') || 'dark');

// --- Initial Load ---
fetchPurchases();