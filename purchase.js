// Helper to get query param
function getQueryParam(name) {
    const url = new URL(window.location.href);
    return url.searchParams.get(name);
}
const purchaseId = getQueryParam('purchaseId');
if (!purchaseId) {
    document.getElementById('receiptDetails').innerHTML = '<span style="color:#ff5c5c;">Invalid purchase link.</span>';
    document.getElementById('timer').style.display = 'none';
} else {
    fetch(`/purchase/${purchaseId}`)
        .then(res => res.json())
        .then(data => {
            if (!data.success) {
                document.getElementById('receiptDetails').innerHTML = '<span style="color:#ff5c5c;">Purchase not found.</span>';
                document.getElementById('timer').style.display = 'none';
                return;
            }
            const p = data.purchase;
            let html = '';
            html += `<div class='receipt-section'><span class='receipt-label'>Purchase ID:</span> #${p.id}</div>`;
            html += `<div class='receipt-section'><span class='receipt-label'>Date:</span> ${new Date(p.created_at).toLocaleString()}</div>`;
            html += `<div class='receipt-section'><span class='receipt-label'>User:</span> ${p.user_email}</div>`;
            html += `<div class='receipt-section'><span class='receipt-label'>Status:</span> ${p.status.charAt(0).toUpperCase() + p.status.slice(1)}</div>`;
            html += `<div class='receipt-section'><span class='receipt-label'>Payment Confirmation:</span> <span id='paymentConfirmationStatus'>${p.payment_confirmation.charAt(0).toUpperCase() + p.payment_confirmation.slice(1)}</span></div>`;
            html += `<div class='receipt-section'><span class='receipt-label'>Items:</span>`;
            html += `<table class='receipt-table'><thead><tr><th>Offer</th><th>Server</th><th>Qty</th><th>Unit Price</th><th>Subtotal</th></tr></thead><tbody>`;
            for (const item of p.items) {
                html += `<tr><td>${item.offer_name}</td><td>${item.server_name}</td><td>${item.quantity}</td><td>$${item.price_per_account.toFixed(2)}</td><td>$${(item.price_per_account * item.quantity).toFixed(2)}</td></tr>`;
            }
            html += `</tbody></table></div>`;
            html += `<div class='receipt-summary'>`;
            html += `<div class='receipt-summary-row'><span>Total before coupon:</span><span>$${p.total_before_coupon.toFixed(2)}</span></div>`;
            if (p.coupon_code) {
                html += `<div class='receipt-summary-row'><span>Coupon (${p.coupon_code}, ${p.coupon_percent}%):</span><span>-$${(p.total_before_coupon - p.subtotal_after_coupon).toFixed(2)}</span></div>`;
            }
            html += `<div class='receipt-summary-row receipt-summary-total'><span>Total to Pay:</span><span>$${p.subtotal_after_coupon.toFixed(2)}</span></div>`;
            html += `</div>`;
            html += `<div class='payment-info'><div class='receipt-label'>Payment Methods (choose any):</div>`;
            for (const net of p.payment_networks) {
                html += `<div style='margin-bottom:8px;'><b>${net.network}:</b> <span style='word-break:break-all;font-family:monospace;font-size:1.1em;'>${net.address}</span></div>`;
            }
            html += `</div>`;
            document.getElementById('receiptDetails').innerHTML = html;
            // Show Paid button if not already confirmed
            if (p.payment_confirmation === 'unconfirmed') {
                document.getElementById('paidBtn').style.display = 'inline-block';
            }
        });
}
// 2-hour timer
let timerSeconds = 2 * 60 * 60;
function updateTimer() {
    if (timerSeconds <= 0) {
        document.getElementById('timer').textContent = 'Time expired. Redirecting to home...';
        document.getElementById('backHomeBtn').style.display = 'inline-block';
        setTimeout(() => {
            window.location.href = '/home.html';
        }, 4000);
        // Optionally clear cart in localStorage/session here if needed
        return;
    }
    const h = Math.floor(timerSeconds / 3600);
    const m = Math.floor((timerSeconds % 3600) / 60);
    const s = timerSeconds % 60;
    document.getElementById('timer').textContent = `Time left to pay: ${h.toString().padStart(2,'0')}:${m.toString().padStart(2,'0')}:${s.toString().padStart(2,'0')}`;
    timerSeconds--;
    setTimeout(updateTimer, 1000);
}
if (purchaseId) updateTimer();
// Paid button logic
document.getElementById('paidBtn').addEventListener('click', async function() {
    this.disabled = true;
    this.textContent = 'Processing...';
    try {
        const res = await fetch(`/purchase/${purchaseId}/confirm-payment`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ payment_confirmation: 'confirmed' })
        });
        if (res.ok) {
            window.location.href = '/home.html';
        } else {
            this.disabled = false;
            this.textContent = 'Paid';
            alert('Error confirming payment. Please try again.');
        }
    } catch {
        this.disabled = false;
        this.textContent = 'Paid';
        alert('Error confirming payment. Please try again.');
    }
});