        // Check if user is logged in (Moved to top for immediate redirection)
        const accessTokenFromStorage = localStorage.getItem('accessToken');
        const accessTokenFromCookie = document.cookie.split('; ').find(row => row.startsWith('accessToken='))?.split('=')[1];
        console.log("Checking authentication on home.html. Current accessToken in localStorage:", accessTokenFromStorage);
        console.log("Checking authentication on home.html. Current accessToken in cookie:", accessTokenFromCookie);
        
        
        if ((!accessTokenFromStorage || accessTokenFromStorage === 'null' || accessTokenFromStorage === 'undefined') && 
            (!accessTokenFromCookie || accessTokenFromCookie === 'null' || accessTokenFromCookie === 'undefined')) {
            console.warn('No valid access token found. Redirecting to login.html...');
            window.location.href = '/login.html';
            // Stop further script execution if not authenticated
            throw new Error("Unauthorized access: Redirecting to login page.");
        }

        // If we have a cookie token but no localStorage token, sync them
        if (accessTokenFromCookie && (!accessTokenFromStorage || accessTokenFromStorage === 'null' || accessTokenFromStorage === 'undefined')) {
            localStorage.setItem('accessToken', accessTokenFromCookie);
        }

        console.log('home.html script started.');
        // Set initial theme from localStorage
        (function() {
            const savedTheme = localStorage.getItem('theme') || 'light';
            document.body.setAttribute('data-theme', savedTheme);
            // Update emoji for initial load
            const themeToggleBtn = document.getElementById('themeToggleBtn');
            if (themeToggleBtn) {
                themeToggleBtn.textContent = savedTheme === 'dark' ? '🌙' : '☀️';
            }
        })();

        // Theme toggle functionality
        function toggleTheme() {
            const currentTheme = document.body.getAttribute('data-theme') || 'light';
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            document.body.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            console.log('Theme toggled to:', newTheme);
            // Update emoji
            const btn = document.getElementById('themeToggleBtn');
            btn.textContent = newTheme === 'dark' ? '🌙' : '☀️';
            // Add animation
            btn.classList.add('animating');
            setTimeout(() => btn.classList.remove('animating'), 400);
        }

        // Attach event listeners for new elements
        document.getElementById('themeToggleBtn').addEventListener('click', toggleTheme);

        // Dropdown functionality
        document.getElementById('userIcon').addEventListener('click', function() {
            this.closest('.dropdown').classList.toggle('show');
        });

        // Handle logout from dropdown
        document.getElementById('dropdownLogoutBtn').addEventListener('click', logout);

        // Close the dropdown if the user clicks outside of it
        window.addEventListener('click', function(event) {
            if (!event.target.matches('#userIcon') && !event.target.closest('.dropdown-content')) {
                const dropdowns = document.getElementsByClassName('dropdown-content');
                for (let i = 0; i < dropdowns.length; i++) {
                    const openDropdown = dropdowns[i];
                    if (openDropdown.closest('.dropdown').classList.contains('show')) {
                        openDropdown.closest('.dropdown').classList.remove('show');
                    }
                }
            }
        });

        // Function to display user's email in dropdown
        function displayUserEmail() {
            console.log('displayUserEmail function called.');
            const token = localStorage.getItem('accessToken');
            console.log('Access Token retrieved:', token, 'Type:', typeof token);
            
            // Ensure token is a non-empty string and not the string "null" or "undefined"
            if (typeof token !== 'string' || token.trim() === '' || token === 'null' || token === 'undefined') {
                console.log('No valid access token found in localStorage (token is null, undefined, or an invalid string literal).');
                // This should ideally not be reached if the top-level authentication check works
                return;
            }

            try {
                const parts = token.split('.');
                console.log('Token parts:', parts, 'Parts length:', parts.length);

                if (parts.length !== 3) {
                    console.error(`Invalid JWT token format. Expected 3 parts separated by dots. Found ${parts.length} parts. Full token value: "${token}"`);
                    return;
                }

                const base64Url = parts[1];
                // Additional check for payload string validity
                if (typeof base64Url !== 'string' || base64Url.length === 0) {
                    console.error(`JWT payload (second part) is empty or not a string. Full token value: "${token}"`);
                    return;
                }

                // Replace URL-safe characters and add padding
                let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
                while (base64.length % 4) {
                    base64 += '=';
                }

                const payload = JSON.parse(atob(base64));
                console.log('Decoded Token Payload:', payload);
                console.log('Value of payload.email:', payload ? payload.email : 'payload is null/undefined'); // Explicitly log email value

                if (payload && payload.email) {
                    document.getElementById('dropdownUserEmail').textContent = payload.email;
                    console.log('User Email displayed:', payload.email);
                } else {
                    console.log('Email not found in token payload or payload is malformed.', payload);
                }
            } catch (error) {
                console.error('Error during JWT decoding or parsing payload:', error, `Problematic token: "${token}"`);
            }
        }

        // Call displayUserEmail on page load (only if authenticated)
        displayUserEmail();

        // Logout functionality
        async function logout() {
            try {
                const response = await fetch('/logout', {
                    method: 'POST',
                    headers: {
                        'Authorization': 'Bearer ' + localStorage.getItem('accessToken')
                    }
                });
                
                // Clear all tokens from localStorage
                localStorage.removeItem('accessToken');
                localStorage.removeItem('refreshToken');
                
                // Redirect to login page
                window.location.href = '/login.html';
            } catch (error) {
                console.error('Logout error:', error);
                // Still redirect to login page even if the server request fails
                window.location.href = '/login.html';
            }
        }

        // Modal elements
        const offerDetailModal = document.getElementById('offerDetailModal');
        const closeModalBtn = document.getElementById('closeModalBtn');
        const modalOfferName = document.getElementById('modalOfferName');
        const modalOfferImage = document.getElementById('modalOfferImage');
        const modalOfferDescription = document.getElementById('modalOfferDescription');
        const modalRegionSelect = document.getElementById('modalRegionSelect');
        const modalQuantityInput = document.getElementById('modalQuantityInput');
        const quantityError = document.getElementById('quantityError');
        const modalPrice = document.getElementById('modalPrice');
        const addToCartBtn = document.getElementById('addToCartBtn');

        let currentOfferData = null; // Store fetched offer data

        // Function to open the modal
        async function openOfferModal(offerId) {
            try {
                const response = await fetch(`/offer-details/${offerId}`);
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                const data = await response.json();

                if (data.success && data.offer) {
                    currentOfferData = data.offer; // Store current offer data

                    modalOfferName.textContent = currentOfferData.header;
                    modalOfferImage.src = `/assets/${encodeURIComponent(decodeURIComponent(currentOfferData.img_url))}.png`;
                    modalOfferImage.alt = currentOfferData.header;
                    modalOfferDescription.innerHTML = currentOfferData.description.replace(/\n/g, '<br>');

                    // Populate region select
                    modalRegionSelect.innerHTML = '';
                    const availableServers = currentOfferData.available_servers ? currentOfferData.available_servers.split(',').map(s => s.trim()) : [];
                    availableServers.forEach(server => {
                        const option = document.createElement('option');
                        option.value = server;
                        option.textContent = server;
                        modalRegionSelect.appendChild(option);
                    });

                    // Set quantity constraints
                    modalQuantityInput.min = currentOfferData.min_quantity || 1;
                    modalQuantityInput.max = currentOfferData.available_quantity || 5000; // Assuming a max if not provided
                    modalQuantityInput.value = currentOfferData.min_quantity || 1; // Default to min quantity

                    // Update price
                    updateModalPrice();

                    // Check and update available quantity info
                    await updateQuantityInfo();

                    offerDetailModal.classList.add('show');
                } else {
                    console.error('Failed to fetch offer details:', data.message);
                    showNotification('error', 'Error', 'Could not load offer details. Please try again.');
                }
            } catch (error) {
                console.error('Error opening offer modal:', error);
                showNotification('error', 'Error', 'An error occurred while loading offer details.');
            }
        }

        // Function to close the modal
        function closeOfferModal() {
            offerDetailModal.classList.remove('show');
            currentOfferData = null; // Clear data when closing
            quantityError.style.display = 'none'; // Hide error message
        }

        // Update modal price based on quantity
        function updateModalPrice() {
            if (currentOfferData) {
                let quantity = parseInt(modalQuantityInput.value);
                if (isNaN(quantity) || quantity < 1) quantity = 0;
                const pricePerAccount = currentOfferData.price_per_acc;
                const totalPrice = quantity * pricePerAccount;
                modalPrice.textContent = `$${totalPrice.toFixed(2)}`;
            }
        }

        // Validate quantity input
        function validateQuantity() {
            const quantity = parseInt(modalQuantityInput.value);
            const min = parseInt(modalQuantityInput.min);
            const max = parseInt(modalQuantityInput.max);

            if (isNaN(quantity) || quantity < min || quantity > max) {
                quantityError.textContent = `Quantity must be between ${min} and ${max}.`;
                quantityError.style.display = 'block';
                addToCartBtn.disabled = true; // Disable add to cart button
                return false;
            } else {
                quantityError.style.display = 'none';
                addToCartBtn.disabled = false;
                return true;
            }
        }

        // Event listeners for modal controls
        modalQuantityInput.addEventListener('input', () => {
            validateQuantity();
            updateModalPrice();
        });

        // Add event listener for server selection changes
        modalRegionSelect.addEventListener('change', () => {
            updateQuantityInfo();
        });

        closeModalBtn.addEventListener('click', closeOfferModal);
        window.addEventListener('click', (event) => {
            if (event.target == offerDetailModal) {
                closeOfferModal();
            }
        });

        // Function to dynamically create and append offer cards
        function createOfferCard(offer) {
            const offerCard = document.createElement('div');
            offerCard.classList.add('offer-card');
            offerCard.dataset.offerId = offer.id; // Store offer ID

            const availableServers = offer.available_servers ? offer.available_servers.split(',').map(s => s.trim().toUpperCase()) : [];
            const firstThreeServers = availableServers.slice(0, 3);
            const remainingServersCount = availableServers.length - firstThreeServers.length;

            // First decode the URL if it's already encoded, then encode it properly, and append .png extension
            const decodedUrl = decodeURIComponent(offer.img_url);
            const imgSrc = `/assets/${encodeURIComponent(decodedUrl)}.png`;

            offerCard.innerHTML = `
                <img src="${imgSrc}" alt="${offer.header}">
                <div class="offer-details">
                    <div class="offer-header">
                        <span class="offer-type">min quantity: ${offer.min_quantity}</span>
                    </div>
                    <div class="offer-title">${offer.header}</div>
                    <div class="offer-tags">
                        ${firstThreeServers.map(server => `<span class="offer-tag">${server}</span>`).join('')}
                        ${remainingServersCount > 0 ? `<span class="offer-tag">+${remainingServersCount} more</span>` : ''}
                    </div>
                    <div class="offer-price">$${offer.price_per_acc.toFixed(2)}</div>
                </div>
            `;
            
            // Add click listener to open modal
            offerCard.addEventListener('click', () => openOfferModal(offer.id));

            return offerCard;
        }

        // Function to fetch and display offers
        async function fetchAndDisplayOffers(type = 'all') {
            try {
                const url = type && type.toLowerCase() !== 'all' ? `/offers?type=${encodeURIComponent(type)}` : '/offers';
                const response = await fetch(url);

                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }

                const data = await response.json();
                const offersGrid = document.getElementById('offersGrid');
                offersGrid.innerHTML = ''; // Clear existing offers

                if (data.success && data.offers.length > 0) {
                    data.offers.forEach(offer => {
                        offersGrid.appendChild(createOfferCard(offer));
                    });
                } else {
                    offersGrid.innerHTML = '<p style="color: var(--text-color);">No offers found for this type.</p>';
                }
            } catch (error) {
                console.error('Error fetching and displaying offers:', error);
                document.getElementById('offersGrid').innerHTML = '<p style="color: var(--text-color);">Error loading offers. Please try again.</p>';
            }
        }

        // Function to populate the offer type filter
        async function populateOfferTypeFilter() {
            try {
                const response = await fetch('/offer-types');
                if (!response.ok) {
                    throw new Error('Failed to fetch offer types');
                }
                const data = await response.json();
                if (data.success) {
                    const filterSelect = document.getElementById('offerTypeFilter');
                    data.types.forEach(type => {
                        const option = document.createElement('option');
                        option.value = type;
                        option.textContent = type;
                        filterSelect.appendChild(option);
                    });
                }
            } catch (error) {
                console.error('Error populating offer type filter:', error);
            }
        }

        // Function to update cart notification badge and block count
        async function updateCartNotification() {
            try {
                const token = localStorage.getItem('accessToken');
                if (!token) {
                    document.getElementById('cartNotificationBadge').classList.remove('show');
                    return;
                }

                // Fetch cart items to count blocks (grouped by server)
                const response = await fetch('/cart', {
                    headers: {
                        'Authorization': 'Bearer ' + token
                    }
                });
                if (!response.ok) throw new Error('Failed to fetch cart');
                const data = await response.json();
                let blockCount = 0;
                if (data.success && data.cart && data.cart.items) {
                    // Group by server
                    const servers = new Set();
                    data.cart.items.forEach(item => {
                        if (item.server_name) servers.add(item.server_name);
                    });
                    blockCount = servers.size;
                }
                const badge = document.getElementById('cartNotificationBadge');
                if (blockCount > 0) {
                    badge.textContent = blockCount;
                    badge.classList.add('show');
                } else {
                    badge.classList.remove('show');
                }
            } catch (error) {
                document.getElementById('cartNotificationBadge').classList.remove('show');
            }
        }

        // Add to Cart button handler
        addToCartBtn.addEventListener('click', async () => {
            if (!currentOfferData || !validateQuantity()) {
                return; // Prevent adding if no offer data or quantity is invalid
            }

            const quantity = parseInt(modalQuantityInput.value);
            const serverName = modalRegionSelect.value;

            const offerToAdd = {
                offerId: currentOfferData.id,
                offerType: currentOfferData.offer_type,
                offerName: currentOfferData.header,
                serverName: serverName,
                quantity: quantity,
                pricePerAccount: currentOfferData.price_per_acc,
                gmailToBeSent: null // You can set this if you collect it in the modal
            };

            try {
                const token = localStorage.getItem('accessToken');
                const response = await fetch('/add-to-cart', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + token
                    },
                    body: JSON.stringify(offerToAdd)
                });

                if (!response.ok) {
                    const errorData = await response.json();
                    
                    // Handle specific error cases with detailed messages
                    if (errorData.currentCartQuantity !== undefined) {
                        const message = errorData.message;
                        const details = `You have ${errorData.currentCartQuantity} in cart. Total available: ${errorData.availableQuantity}. Max you can add: ${errorData.maxQuantityToAdd || 0}.`;
                        throw new Error(`${message}\n\n${details}`);
                    } else {
                    throw new Error(`Failed to add to cart: ${errorData.message || response.statusText}`);
                    }
                }

                const result = await response.json();
                showNotification('success', 'Success', result.message);
                closeOfferModal();
                updateCartNotification(); // Update cart count after adding item

            } catch (error) {
                console.error('Error adding to cart:', error);
                showNotification('error', 'Error', error.message || 'Failed to add item to cart. Please try again.');
            }
        });

        // Initial load of offers and cart notification
        populateOfferTypeFilter();
        fetchAndDisplayOffers();
        updateCartNotification();

        // Add event listener for the filter
        document.getElementById('offerTypeFilter').addEventListener('change', (event) => {
            const selectedType = event.target.value;
            fetchAndDisplayOffers(selectedType);
        });

        // Notification functions
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
            
            // Add event listener for close button
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
            
            // Trigger animation
            setTimeout(() => {
                notification.classList.add('show');
            }, 100);
            
            // Auto remove after duration
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

        // Function to check available quantity for current offer and server
        async function checkAvailableQuantity(offerId, serverName) {
            try {
                const token = localStorage.getItem('accessToken');
                if (!token) return null;

                // Get current cart to calculate available quantity
                const cartResponse = await fetch('/cart', {
                    headers: {
                        'Authorization': 'Bearer ' + token
                    }
                });

                if (!cartResponse.ok) return null;

                const cartData = await cartResponse.json();
                let currentCartQuantity = 0;

                if (cartData.success && cartData.cart && cartData.cart.items) {
                    // Sum up quantities for items with same offer_id and server_name
                    currentCartQuantity = cartData.cart.items
                        .filter(item => item.offer_id == offerId && item.server_name === serverName)
                        .reduce((sum, item) => sum + item.quantity, 0);
                }

                // Get offer details to find total available quantity
                const offerResponse = await fetch(`/offer-details/${offerId}`);
                if (!offerResponse.ok) return null;

                const offerData = await offerResponse.json();
                if (!offerData.success) return null;

                const totalAvailable = offerData.offer.available_quantity;
                const maxCanAdd = totalAvailable - currentCartQuantity;

                return {
                    currentCartQuantity: currentCartQuantity,
                    totalAvailable: totalAvailable,
                    maxCanAdd: Math.max(0, maxCanAdd)
                };
            } catch (error) {
                console.error('Error checking available quantity:', error);
                return null;
            }
        }

        // Function to update quantity input with available quantity info
        async function updateQuantityInfo() {
            if (!currentOfferData || !modalRegionSelect.value) return;

            const quantityInfo = await checkAvailableQuantity(currentOfferData.id, modalRegionSelect.value);
            
            if (quantityInfo) {
                const quantityLabel = document.getElementById('quantityLabel');
                if (quantityLabel) {
                    quantityLabel.textContent = `Quantity (You have ${quantityInfo.currentCartQuantity} in cart. Max you can add: ${quantityInfo.maxCanAdd})`;
                }

                // Update max attribute of quantity input
                modalQuantityInput.max = quantityInfo.maxCanAdd;
                
                // If current quantity exceeds max, adjust it
                if (parseInt(modalQuantityInput.value) > quantityInfo.maxCanAdd) {
                    modalQuantityInput.value = Math.max(currentOfferData.min_quantity, quantityInfo.maxCanAdd);
                }

                // Disable add button if nothing can be added
                if (quantityInfo.maxCanAdd <= 0) {
                    addToCartBtn.disabled = true;
                    addToCartBtn.textContent = 'Already at maximum quantity';
                } else {
                    addToCartBtn.disabled = false;
                    addToCartBtn.textContent = 'Add to Cart';
                }
            }
        }

        // Make cart icon go to cart.html
        document.getElementById('cartIcon').addEventListener('click', function() {
            window.location.href = '/cart.html';
        });
