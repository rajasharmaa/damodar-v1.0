


function loadinganimation() {
  gsap.from("#head,#head1,.pera1", {
    y: 100,
    opacity: 0,
    delay: 0.5,
    duration: 0.9,
    stagger: 0.3,
  });
  gsap.from("nav,medias", {
    
    scale: 0.9,
    opacity: 0,
    delay: 1.3,
    duration: 0.5,
  });
}
loadinganimation();








 

// Industrial Pipe Background Animation
function createIndustrialBackground() {
  const pipesContainer = document.querySelector('.pipes-container');
  const particlesContainer = document.querySelector('.particles-container');
  const colors = ['rgba(58, 123, 213, 0.1)', 'rgba(65, 131, 215, 0.15)', 'rgba(72, 139, 217, 0.2)'];
  
  // Create horizontal pipes
  for (let i = 0; i < 8; i++) {
    const pipe = document.createElement('div');
    pipe.className = 'pipe';
    pipesContainer.appendChild(pipe);
    
    const isVertical = Math.random() > 0.5;
    const duration = gsap.utils.random(30, 50);
    const size = gsap.utils.random(10, 30);
    const length = gsap.utils.random(200, 400);
    
    gsap.set(pipe, {
      width: isVertical ? `${size}px` : `${length}px`,
      height: isVertical ? `${length}px` : `${size}px`,
      background: colors[Math.floor(Math.random() * colors.length)],
      x: isVertical ? gsap.utils.random(0, window.innerWidth) : -length,
      y: isVertical ? -length : gsap.utils.random(0, window.innerHeight)
    });
    
    gsap.to(pipe, {
      x: isVertical ? gsap.utils.random(0, window.innerWidth) : window.innerWidth + length,
      y: isVertical ? window.innerHeight + length : gsap.utils.random(0, window.innerHeight),
      duration: duration,
      ease: "none",
      repeat: -1
    });
  }
  
  // Create pipe connectors
  for (let i = 0; i < 15; i++) {
    const connector = document.createElement('div');
    connector.className = 'pipe-connector';
    pipesContainer.appendChild(connector);
    
    const size = gsap.utils.random(15, 40);
    
    gsap.set(connector, {
      width: `${size}px`,
      height: `${size}px`,
      x: gsap.utils.random(0, window.innerWidth),
      y: gsap.utils.random(0, window.innerHeight),
      opacity: 0
    });
    
    gsap.to(connector, {
      opacity: 0.3,
      duration: gsap.utils.random(3, 6),
      yoyo: true,
      repeat: -1,
      delay: gsap.utils.random(0, 5)
    });
  }
  
  // Create floating particles (weld sparks)
  for (let i = 0; i < 20; i++) {
    const particle = document.createElement('div');
    particle.className = 'particle';
    particlesContainer.appendChild(particle);
    
    const size = gsap.utils.random(2, 6);
    
    gsap.set(particle, {
      width: `${size}px`,
      height: `${size}px`,
      x: gsap.utils.random(0, window.innerWidth),
      y: gsap.utils.random(0, window.innerHeight),
      opacity: 0
    });
    
    // Spark animation
    const tl = gsap.timeline({ repeat: -1, delay: gsap.utils.random(0, 5) });
    tl.to(particle, {
      opacity: 0.8,
      duration: 0.3,
      ease: "power1.out"
    })
    .to(particle, {
      x: "+=50",
      y: "+=50",
      duration: 0.8,
      ease: "power1.inOut"
    })
    .to(particle, {
      opacity: 0,
      duration: 0.3,
      ease: "power1.in"
    });
  }
}

// Initialize when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  createIndustrialBackground();
  
  // Make background responsive to window resize
  window.addEventListener('resize', () => {
    document.querySelector('.pipes-container').innerHTML = '';
    document.querySelector('.particles-container').innerHTML = '';
    createIndustrialBackground();
  });
});