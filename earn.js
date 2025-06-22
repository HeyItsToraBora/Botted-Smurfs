document.querySelectorAll('.plan-btn').forEach(btn => {
    btn.addEventListener('click', function() {
        const link = btn.getAttribute('data-link');
        if (link) window.location.href = link;
    });
});