const token = localStorage.getItem('accessToken');
if (!token) {
    window.location.href = '/login.html';
}

let cart = [];
let couponValue = 0;
let selectedPayment = 'crypto';
let selectedCrypto = 'USDT';
let selectedNetworkAddress = '';
let appliedCoupon = null;
let savedEmail = null;
let isEmailSaved = false;
let userEmail = null;

async function fetchCart() {
    try {
        const response = await fetch('/cart', {
            headers: {
                'Authorization': 'Bearer ' + token
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.success && data.cart && data.cart.items) {
                cart = data.cart.items.map(item => ({
                    id: item.item_id,
                    offer_id: item.offer_id,
                    title: item.offer_name,
                    price: item.price_per_account,
                    quantity: item.quantity,
                    server: item.server_name,
                    img: `/assets/${item.img_url || 'logo'}.png`,
                    minQuantity: item.min_quantity || 1,
                    availableQuantity: item.available_quantity || 999
                }));
            } else {
                cart = [];
            }
            renderCart();
            
            
            await fetchAppliedCoupon();
            
            
            await fetchUserEmail();
        } else {
            cart = [];
            renderCart();
        }
    } catch (err) {
        cart = [];
        renderCart();
    }
}

function renderCart() {
    const cartItems = document.getElementById('cartItems');
    cartItems.innerHTML = '';

    if (!cart || cart.length === 0) {
        cartItems.innerHTML = '<p style="text-align: center; color: var(--text-color-secondary); padding: 2rem 0;">Your cart is empty.</p>';
        updateSummary();
        return;
    }

    
    const groupedItems = {};
    cart.forEach(item => {
        
        const groupKey = `${item.offer_id}_${item.server}`;
        if (!groupedItems[groupKey]) {
            groupedItems[groupKey] = {
                items: [],
                offer_id: item.offer_id,
                server: item.server,
                title: item.title,
                img: item.img,
                minQuantity: item.minQuantity,
                availableQuantity: item.availableQuantity
            };
        }
        groupedItems[groupKey].items.push(item);
    });

    Object.keys(groupedItems).forEach(groupKey => {
        const group = groupedItems[groupKey];
        const totalQuantity = group.items.reduce((sum, item) => sum + item.quantity, 0);
        const totalPrice = group.items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
        
        let imgSrc = group.img;
        if (imgSrc && !imgSrc.startsWith('/')) {
            imgSrc = '/' + imgSrc;
        }

        const div = document.createElement('div');
        div.className = 'cart-item';
        div.innerHTML = `
            <img src="${imgSrc}" alt="${group.title}" onerror="this.onerror=null;this.src='/assets/logo.png';">
            <div class="cart-item-details">
                <div class="cart-item-title">${group.title}</div>
                <div class="cart-item-tags">
                    <span class="cart-tag">${group.server}</span>
                    <span class="cart-tag" id="group-quantity-${groupKey}">${totalQuantity}x</span>
                </div>
                <div class="cart-item-qty">
                    <button class="qty-btn" data-group-key="${groupKey}" data-delta="-1">-</button>
                    <span id="group-quantity-display-${groupKey}">${totalQuantity}</span>
                    <button class="qty-btn" data-group-key="${groupKey}" data-delta="1">+</button>
                </div>
            </div>
            <div class="cart-item-price" id="group-price-${groupKey}">$${totalPrice.toFixed(2)}</div>
            <button class="cart-item-remove" data-group-key="${groupKey}">🗑️</button>
        `;
        cartItems.appendChild(div);
    });

    updateSummary();
    attachCartEventListeners();
}

function attachCartEventListeners() {
    document.querySelectorAll('.qty-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const groupKey = this.getAttribute('data-group-key');
            const delta = parseInt(this.getAttribute('data-delta'));
            updateQty(groupKey, delta);
        });
    });
    document.querySelectorAll('.cart-item-remove').forEach(btn => {
        btn.addEventListener('click', function() {
            const groupKey = this.getAttribute('data-group-key');
            removeItem(groupKey);
        });
    });
}

function updateQty(groupKey, delta) {
    const groupItems = cart.filter(item => `${item.offer_id}_${item.server}` === groupKey);
    if (groupItems.length === 0) return;

    const currentTotalQuantity = groupItems.reduce((sum, item) => sum + item.quantity, 0);
    const newTotalQuantity = currentTotalQuantity + delta;
    const minQuantity = groupItems[0].minQuantity;
    const availableQuantity = groupItems[0].availableQuantity;

    if (newTotalQuantity > 0 && newTotalQuantity < minQuantity) {
        showNotification('error', 'Quantity Error', `Minimum quantity for this offer is ${minQuantity}.`);
        return;
    }

    if (newTotalQuantity > availableQuantity) {
        showNotification('error', 'Quantity Error', `Only ${availableQuantity} items available for this offer.`);
        return;
    }

    if (newTotalQuantity <= 0) {
        removeItem(groupKey);
    } else {
        updateQuantityInDatabase(groupKey, newTotalQuantity);
    }
}

async function updateQuantityInDatabase(groupKey, quantity) {
    try {
        const groupItems = cart.filter(item => `${item.offer_id}_${item.server}` === groupKey);
        const itemIds = groupItems.map(item => item.id);

        for (const itemId of itemIds) {
            const response = await fetch(`/cart/item/${itemId}/quantity`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + token
                },
                body: JSON.stringify({ quantity: Math.ceil(quantity / itemIds.length) })
            });

            if (!response.ok) {
                const errorData = await response.json();
                showNotification('error', 'Quantity Error', `Error updating quantity: ${errorData.message}`);
                return;
            }
        }

        await fetchCart();
    } catch (error) {
        console.error('Error updating quantity:', error);
        showNotification('error', 'Quantity Error', 'Error updating quantity. Please try again.');
    }
}

async function removeItem(groupKey) {
    try {
        const groupItems = cart.filter(item => `${item.offer_id}_${item.server}` === groupKey);
        const itemIds = groupItems.map(item => item.id);

        for (const itemId of itemIds) {
            const response = await fetch(`/cart/item/${itemId}`, {
                method: 'DELETE',
                headers: { 'Authorization': 'Bearer ' + token }
            });

            if (!response.ok) {
                const errorData = await response.json();
                showNotification('error', 'Remove Error', `Error removing item: ${errorData.message}`);
                return;
            }
        }

        await fetchCart();
    } catch (error) {
        console.error('Error removing item:', error);
        showNotification('error', 'Remove Error', 'Error removing item. Please try again.');
    }
}

function updateSummary() {
    let subtotal = cart.reduce((sum, item) => sum + item.price * item.quantity, 0);
    let total = subtotal - couponValue;
    document.getElementById('subtotal').textContent = `$${subtotal.toFixed(2)}`;
    document.getElementById('total').textContent = `$${total.toFixed(2)}`;
}

async function fetchAppliedCoupon() {
    try {
        const response = await fetch('/cart/applied-coupon', {
            headers: {
                'Authorization': 'Bearer ' + token
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.success && data.appliedCoupon) {
                appliedCoupon = data.appliedCoupon;
                couponValue = appliedCoupon.coupon_discount_amount;
                showAppliedCoupon();
            } else {
                appliedCoupon = null;
                couponValue = 0;
                hideAppliedCoupon();
            }
            updateSummary();
        }
    } catch (error) {
        console.error('Error fetching applied coupon:', error);
    }
}

function showAppliedCoupon() {
    const display = document.getElementById('appliedCouponDisplay');
    display.style.display = 'block';
    display.innerHTML = `
        <div class="applied-coupon">
            <div class="coupon-info">
                <div class="coupon-name">${appliedCoupon.coupon.name}</div>
                <div class="coupon-discount">Discount: $${appliedCoupon.coupon_discount_amount.toFixed(2)} (${appliedCoupon.coupon.percentage_per_purchase}% off)</div>
            </div>
            <button class="remove-btn" id="removeCouponBtn">Remove</button>
        </div>
    `;
    
    // Add event listener for remove button
    document.getElementById('removeCouponBtn').addEventListener('click', removeCoupon);
    
    // Disable coupon input and apply button
    document.getElementById('couponInput').disabled = true;
    document.getElementById('applyCouponBtn').disabled = true;
}

function hideAppliedCoupon() {
    const display = document.getElementById('appliedCouponDisplay');
    display.style.display = 'none';
    display.innerHTML = '';
    
    // Enable coupon input and apply button
    document.getElementById('couponInput').disabled = false;
    document.getElementById('applyCouponBtn').disabled = false;
}

async function applyCoupon() {
    const code = document.getElementById('couponInput').value.trim();
    if (!code) {
        showNotification('error', 'Coupon Error', 'Please enter a coupon code.');
        return;
    }

    try {
        const response = await fetch('/cart/apply-coupon', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token
            },
            body: JSON.stringify({ couponCode: code })
        });
        
        const data = await response.json();
        if (data.success) {
            appliedCoupon = {
                coupon: data.coupon,
                coupon_discount_amount: data.discountAmount
            };
            couponValue = data.discountAmount;
            showAppliedCoupon();
            updateSummary();
            showNotification('success', 'Coupon Applied', 'Coupon applied successfully!');
            document.getElementById('couponInput').value = '';
        } else {
            showNotification('error', 'Coupon Error', data.message || 'Failed to apply coupon.');
        }
    } catch (error) {
        console.error('Error applying coupon:', error);
        showNotification('error', 'Coupon Error', 'Error applying coupon. Please try again.');
    }
}

async function removeCoupon() {
    try {
        console.log('Removing coupon...');
        const response = await fetch('/cart/remove-coupon', {
            method: 'DELETE',
            headers: {
                'Authorization': 'Bearer ' + token
            }
        });
        
        console.log('Remove coupon response status:', response.status);
        const data = await response.json();
        console.log('Remove coupon response data:', data);
        
        if (data.success) {
            appliedCoupon = null;
            couponValue = 0;
            hideAppliedCoupon();
            updateSummary();
            
            // Refresh the applied coupon info from server
            await fetchAppliedCoupon();
            
            showNotification('success', 'Coupon Removed', 'Coupon removed successfully!');
        } else {
            showNotification('error', 'Coupon Error', data.message || 'Failed to remove coupon.');
        }
    } catch (error) {
        console.error('Error removing coupon:', error);
        showNotification('error', 'Coupon Error', 'Error removing coupon. Please try again.');
    }
}

function selectPayment(method) {
    // No longer needed, only crypto is available
}

async function getMinOrderPrice() {
    try {
        const res = await fetch('/api/config/min-order-price');
        const data = await res.json();
        if (data.success) return parseFloat(data.value);
    } catch {}
    return 0;
}

async function proceedToPayment() {
    if (!isEmailSaved || !savedEmail) {
        showNotification('error', 'Email Required', 'Please save your Gmail for delivery first.');
        return;
    }
    // Check min order price
    const minOrderPrice = await getMinOrderPrice();
    let subtotal = cart.reduce((sum, item) => sum + item.price * item.quantity, 0);
    let total = subtotal - couponValue;
    const minMsg = document.getElementById('minOrderPriceMsg');
    if (total < minOrderPrice) {
        minMsg.textContent = `Your order total ($${total.toFixed(2)}) is below the minimum order value of $${minOrderPrice.toFixed(2)}.`;
        return;
    } else {
        minMsg.textContent = '';
    }
    // Disable button to prevent double submission
    const btn = document.getElementById('proceedBtn');
    btn.disabled = true;
    btn.textContent = 'Processing...';
    // Gather payment info
    const payment_currency = selectedCrypto;
    // Fetch all networks for the selected coin
    let payment_networks = [];
    try {
        const networksRes = await fetch(`/api/crypto/networks/${encodeURIComponent(payment_currency)}`);
        const networksData = await networksRes.json();
        if (networksData.success && networksData.networks.length) {
            payment_networks = networksData.networks.map(n => ({ network: n.name, address: n.address }));
        }
    } catch {}
    const total_before_coupon = subtotal;
    const coupon_code = appliedCoupon ? appliedCoupon.coupon.name : null;
    const coupon_percent = appliedCoupon ? appliedCoupon.coupon.percentage_per_purchase : null;
    const subtotal_after_coupon = total;
    try {
        const response = await fetch('/purchase', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token
            },
            body: JSON.stringify({
                payment_currency,
                payment_networks,
                total_before_coupon,
                coupon_code,
                coupon_percent,
                subtotal_after_coupon
            })
        });
        const data = await response.json();
        if (data.success && data.purchaseId) {
            window.location.href = `/purchase.html?purchaseId=${data.purchaseId}`;
        } else {
            showNotification('error', 'Purchase Error', data.message || 'Failed to create purchase.');
            btn.disabled = false;
            btn.textContent = 'Proceed to Payment';
        }
    } catch (error) {
        showNotification('error', 'Purchase Error', 'Error creating purchase. Please try again.');
        btn.disabled = false;
        btn.textContent = 'Proceed to Payment';
    }
}

async function saveEmail() {
    const emailInput = document.getElementById('gmailDelivery');
    const email = emailInput.value.trim();
    
    if (!email) {
        showNotification('error', 'Email Error', 'Please enter a valid email address for delivery.');
        return;
    }
    
    if (!isValidEmail(email)) {
        showNotification('error', 'Email Error', 'Please enter a valid email address.');
        return;
    }
    
    try {
        // Update gmail in database for all cart items
        const response = await fetch('/cart/update-gmail', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token
            },
            body: JSON.stringify({ gmail: email })
        });
        
        const data = await response.json();
        if (!data.success) {
            showNotification('error', 'Email Error', 'Failed to save email. Please try again.');
            return;
        }
        
        savedEmail = email;
        isEmailSaved = true;
        
        // Disable input and change button
        emailInput.disabled = true;
        emailInput.value = email;
        
        // Change save button to edit button
        const saveBtn = document.querySelector('.save-email-btn');
        saveBtn.textContent = 'Edit';
        saveBtn.className = 'edit-email-btn';
        
        // Remove old event listener and add new one
        saveBtn.removeEventListener('click', saveEmail);
        saveBtn.addEventListener('click', editEmail);
        
        // Add saved email indicator
        const emailContainer = document.querySelector('.email-container');
        let savedIndicator = emailContainer.querySelector('.saved-email');
        if (!savedIndicator) {
            savedIndicator = document.createElement('div');
            savedIndicator.className = 'saved-email';
            emailContainer.appendChild(savedIndicator);
        }
        savedIndicator.textContent = `✓ Delivery email saved: ${email}`;
        
    } catch (error) {
        console.error('Error saving email:', error);
        showNotification('error', 'Email Error', 'Error saving email. Please try again.');
    }
}

function editEmail() {
    const emailInput = document.getElementById('gmailDelivery');
    const editBtn = document.querySelector('.edit-email-btn');
    
    // Enable input
    emailInput.disabled = false;
    emailInput.focus();
    
    // Change edit button back to save button
    editBtn.textContent = 'Save';
    editBtn.className = 'save-email-btn';
    
    // Remove old event listener and add new one
    editBtn.removeEventListener('click', editEmail);
    editBtn.addEventListener('click', saveEmail);
    
    // Remove saved email indicator
    const savedIndicator = document.querySelector('.saved-email');
    if (savedIndicator) {
        savedIndicator.remove();
    }
    
    isEmailSaved = false;
}

function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

async function fetchUserEmail() {
    try {
        // Decode JWT token to get user email
        const tokenParts = token.split('.');
        const payload = JSON.parse(atob(tokenParts[1]));
        userEmail = payload.email;
        
        // Add user profile email indicator (but don't disable the delivery input)
        const emailContainer = document.querySelector('.email-container');
        let profileIndicator = emailContainer.querySelector('.profile-email');
        if (!profileIndicator) {
            profileIndicator = document.createElement('div');
            profileIndicator.className = 'profile-email';
            profileIndicator.style.color = '#6b7280';
            profileIndicator.style.fontSize = '0.8rem';
            profileIndicator.style.marginBottom = '8px';
            emailContainer.insertBefore(profileIndicator, emailContainer.firstChild);
        }
        profileIndicator.textContent = `Profile email: ${userEmail}`;
        
    } catch (error) {
        console.error('Error fetching user email:', error);
    }
}

// Attach event listeners for static elements
document.getElementById('applyCouponBtn').addEventListener('click', applyCoupon);
document.getElementById('proceedBtn').addEventListener('click', proceedToPayment);
document.querySelector('.save-email-btn').addEventListener('click', saveEmail);
document.getElementById('cryptoSelect').addEventListener('change', function() {
    const selectedOption = this.options[this.selectedIndex];
    if (selectedOption) {
        selectedCrypto = selectedOption.value.split('|')[0];
        selectedNetworkAddress = selectedOption.dataset.address;
    }
});

// Initial load
fetchCart();

// Add or update the showNotification function if not present
if (typeof showNotification !== 'function') {
    function showNotification(type, title, message, duration = 5000) {
        const container = document.getElementById('notificationContainer');
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        const icon = type === 'success' ? '✅' : type === 'error' ? '❌' : 'ℹ️';
        notification.innerHTML = `
            <div class="notification-icon">${icon}</div>
            <div class="notification-content">
                <div class="notification-title">${title}</div>
                <div class="notification-message">${message}</div>
            </div>
            <button class="notification-close">×</button>
        `;
        const closeBtn = notification.querySelector('.notification-close');
        closeBtn.addEventListener('click', () => {
            notification.classList.remove('show');
            setTimeout(() => {
                if (notification.parentElement) {
                    notification.remove();
                }
            }, 300);
        });
        container.appendChild(notification);
        setTimeout(() => {
            notification.classList.add('show');
        }, 100);
        if (duration > 0) {
            setTimeout(() => {
                notification.classList.remove('show');
                setTimeout(() => {
                    if (notification.parentElement) {
                        notification.remove();
                    }
                }, 300);
            }, duration);
        }
    }
}

// Set initial theme from localStorage (home.html logic)
(function() {
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.body.setAttribute('data-theme', savedTheme);
    // Update emoji for initial load
    const themeToggleBtn = document.getElementById('themeToggleBtn');
    if (themeToggleBtn) {
        themeToggleBtn.textContent = savedTheme === 'dark' ? '🌙' : '☀️';
    }
})();

// Theme toggle functionality (home.html logic)
function toggleTheme() {
    const currentTheme = document.body.getAttribute('data-theme') || 'light';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    document.body.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    // Update emoji
    const btn = document.getElementById('themeToggleBtn');
    btn.textContent = newTheme === 'dark' ? '🌙' : '☀️';
    // Add animation
    btn.classList.add('animating');
    setTimeout(() => btn.classList.remove('animating'), 400);
}
document.getElementById('themeToggleBtn').addEventListener('click', toggleTheme);

// === Dynamic Crypto Dropdown (Coin Only) ===
async function populateCryptoDropdown() {
    const select = document.getElementById('cryptoSelect');
    select.innerHTML = '<option disabled selected>Loading...</option>';
    try {
        const coinsRes = await fetch('/api/crypto/coins');
        const coinsData = await coinsRes.json();
        if (!coinsData.success || !coinsData.coins.length) {
            select.innerHTML = '<option disabled selected>No cryptocurrencies available</option>';
            return;
        }
        select.innerHTML = '';
        for (const coin of coinsData.coins) {
            const option = document.createElement('option');
            option.value = coin.symbol;
            option.textContent = `${coin.name} (${coin.symbol})`;
            select.appendChild(option);
        }
        // Set selectedCrypto to first coin and fetch its first network/address
        select.selectedIndex = 0;
        selectedCrypto = coinsData.coins[0].symbol;
        await fetchFirstNetworkAddress(selectedCrypto);
    } catch (err) {
        select.innerHTML = `<option disabled selected>Error loading cryptocurrencies</option>`;
    }
}
async function fetchFirstNetworkAddress(coinSymbol) {
    try {
        const networksRes = await fetch(`/api/crypto/networks/${encodeURIComponent(coinSymbol)}`);
        const networksData = await networksRes.json();
        if (networksData.success && networksData.networks.length) {
            selectedNetworkAddress = networksData.networks[0].address;
        } else {
            selectedNetworkAddress = '';
        }
    } catch {
        selectedNetworkAddress = '';
    }
}
document.getElementById('cryptoSelect').addEventListener('change', async function() {
    selectedCrypto = this.value;
    await fetchFirstNetworkAddress(selectedCrypto);
});
// Call on page load
populateCryptoDropdown();
// === End Dynamic Crypto Dropdown (Coin Only) ===
