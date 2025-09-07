document.addEventListener('DOMContentLoaded', function() {

    // ===================================
    // IMPROVED Mobile Menu Functionality
    // ===================================
    const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
    const headerLinks = document.querySelector('.header-links');

    if (mobileMenuBtn && headerLinks) {
        mobileMenuBtn.addEventListener('click', function() {
            // Toggling a class is more robust for controlling styles with CSS
            headerLinks.classList.toggle('active');
            // Animate hamburger icon
            mobileMenuBtn.classList.toggle('active');
        });
    }

    // ===================================
    // Blog Post Display Functionality
    // ===================================
    const blogCards = document.querySelectorAll('.blog-card');
    const displayContainer = document.getElementById('blog-display-container');

    if (blogCards.length > 0 && displayContainer) {
        blogCards.forEach(card => {
            card.addEventListener('click', () => {
                const postId = card.getAttribute('data-post');
                const postContentElement = document.getElementById(postId);

                if (postContentElement) {
                    const clonedContent = postContentElement.cloneNode(true);
                    
                    const closeButton = document.createElement('a');
                    closeButton.className = 'close-btn';
                    closeButton.innerText = 'Close Post';
                    closeButton.style.cursor = 'pointer';
                    closeButton.onclick = () => {
                        displayContainer.classList.remove('visible');
                        setTimeout(() => { displayContainer.innerHTML = ''; }, 500);
                    };

                    displayContainer.innerHTML = '';
                    displayContainer.appendChild(clonedContent);
                    displayContainer.appendChild(closeButton);
                    
                    displayContainer.classList.add('visible');
                    displayContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            });
        });
    }

    // ===================================
    // Image Fallback (Your existing code)
    // ===================================
    const campusImage = document.getElementById('campus-image');
    if (campusImage && campusImage.naturalWidth === 0) {
        campusImage.src = 'https://images.unsplash.com/photo-1523050854058-8df90110c9f1?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=1000&q=80';
        campusImage.alt = 'University campus safety';
    }

    // ===================================
    // Scroll Effect (Your existing code)
    // ===================================
    const nextSection = document.querySelector('.next-section');
    const firstPage = document.querySelector('.first-page');
    
    if ('IntersectionObserver' in window && nextSection && firstPage) {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    firstPage.style.background = 'linear-gradient(to bottom, #2f2929ff, #000000)';
                } else {
                    firstPage.style.background = 'linear-gradient(to bottom, #2f2929ff, #1a1a1a)';
                }
            });
        }, { threshold: 0.1 });
        
        observer.observe(nextSection);
    }

    // ===================================
    // Animation on Scroll for elements without AOS
    // ===================================
    const animateOnScroll = () => {
        const elements = document.querySelectorAll('.fade-in, .slide-in-left, .slide-in-right');
        
        elements.forEach(element => {
            const elementPosition = element.getBoundingClientRect().top;
            const screenPosition = window.innerHeight / 1.3;
            
            if (elementPosition < screenPosition) {
                element.classList.add('visible');
            }
        });
    };

    // Initial check and add scroll listener
    window.addEventListener('scroll', animateOnScroll);
    animateOnScroll(); // Check on load

    // ===================================
    // Pulse animation for CTA buttons
    // ===================================
    const ctaButtons = document.querySelectorAll('.cta-btn, .cta-button, .demo-btn');
    ctaButtons.forEach(button => {
        setInterval(() => {
            button.classList.add('pulse');
            setTimeout(() => {
                button.classList.remove('pulse');
            }, 1000);
        }, 5000);
    });

    // ===================================
    // Parallax effect for hero image
    // ===================================
    const heroImage = document.querySelector('.image-container');
    if (heroImage) {
        window.addEventListener('scroll', () => {
            const scrolled = window.pageYOffset;
            const rate = scrolled * -0.5;
            heroImage.style.transform = `translateY(${rate}px) scale(${1 + Math.abs(rate)*0.0002})`;
        });
    }

    // ===================================
    // Hover effect for team member images
    // ===================================
    const teamImages = document.querySelectorAll('.team-member-card img');
    teamImages.forEach(img => {
        img.addEventListener('mouseenter', () => {
            img.style.transform = 'scale(1.1)';
            img.style.transition = 'transform 0.5s ease';
        });
        
        img.addEventListener('mouseleave', () => {
            img.style.transform = 'scale(1)';
        });
    });

    
});