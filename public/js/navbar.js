// This function is called by the parent page after it fetches user data.
// It populates the navbar with the provided user information.
async function populateNavbar(user) {
  const rightNavLi = document.querySelector('.right-nav');
  const navHome = document.getElementById('nav-home');
  const navBannerLink = document.getElementById('nav-banner-link');
  const navLobby = document.querySelector('a[href="/lobby.html"]');
  const navMyStats = document.querySelector('a[href="/player.html"]');
  const navProfileSettings = document.querySelector('a[href="/profile-settings.html"]');

  // Safety check for navbar elements
  if (!rightNavLi || !navHome || !navBannerLink || !navLobby || !navMyStats || !navProfileSettings) {
    console.error("One or more navbar elements could not be found.");
    return;
  }

  if (!user) {
    document.querySelector('nav').classList.add('logged-out');
    // User is not logged in, show the login button and hide protected links.
    navHome.href = '/';
    navBannerLink.href = '/';
    navLobby.parentElement.style.display = 'none';
    navMyStats.parentElement.style.display = 'none';
    navProfileSettings.parentElement.style.display = 'none';

    rightNavLi.innerHTML = `
      <a href="/auth/steam" class="greensteam-button" style="text-decoration: none; text-align: center;">
        Sign in with Steam
      </a>
    `;
    return;
  }

  // User is logged in. Populate the navbar with their details.
  const navbarUsername = document.getElementById('navbarUsername');
  navbarUsername.textContent = user.username;
  navbarUsername.addEventListener('click', () => {
    window.location.href = '/profile-settings.html';
  });
  
  const profileImg = document.getElementById('navbarProfile');
  profileImg.src = user.profilePictureUrl || '/img/fallback-pfp.png';
  profileImg.onerror = function() {
    this.src = '/img/fallback-pfp.png';
  };
  
  navHome.href = '/profile.html';
  navBannerLink.href = '/profile.html';

  // Fetch the user's ELO rating.
  try {
    const eloRes = await fetch('/user/skill', { credentials: 'include' });
    if (eloRes.ok) {
      const eloData = await eloRes.json();
      document.getElementById('navbarElo').textContent = `ELO: ${eloData.skill || 0}`;
    } else {
      document.getElementById('navbarElo').textContent = 'ELO: 0';
    }
  } catch (error) {
    console.error('Failed to fetch ELO for navbar:', error);
    document.getElementById('navbarElo').textContent = 'ELO: 0';
  }
}
