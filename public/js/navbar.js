// This function is called by the parent page after it fetches user data.
// It populates the navbar with the provided user information.
async function populateNavbar(user) {
  const rightNavLi = document.querySelector('.right-nav');
  const navHome = document.getElementById('nav-home');
  const navLobby = document.querySelector('a[href="/lobby.html"]');
  const navMyStats = document.querySelector('a[href="/player.html"]');
  const navProfileSettings = document.querySelector('a[href="/profile-settings.html"]');

  // Safety check for navbar elements
  if (!rightNavLi || !navHome || !navLobby || !navMyStats || !navProfileSettings) {
    console.error("One or more navbar elements could not be found.");
    return;
  }

  if (!user) {
    // User is not logged in, show the login button and hide protected links.
    navHome.href = '/';
    navLobby.parentElement.style.display = 'none';
    navMyStats.parentElement.style.display = 'none';
    navProfileSettings.parentElement.style.display = 'none';

    rightNavLi.innerHTML = `
      <a href="/auth/steam" style="text-decoration: none;">
        <button class="greensteam-button" style="padding: 8px 16px; vertical-align: middle;">
          Sign in with Steam
        </button>
      </a>
    `;
    return;
  }

  // User is logged in. Populate the navbar with their details.
  document.getElementById('navbarUsername').textContent = user.username;
  
  const profileImg = document.getElementById('navbarProfile');
  profileImg.src = user.profilePictureUrl || '/img/fallback-pfp.png';
  profileImg.onerror = function() {
    this.src = '/img/fallback-pfp.png';
  };
  
  navHome.href = '/profile.html';

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
