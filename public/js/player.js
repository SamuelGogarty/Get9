async function loadPlayerStats(playerId) {
  try {
    document.querySelector('.loading-spinner').style.display = 'block';
    
    const response = await fetch(`/api/player/${playerId}/stats`);
    if (!response.ok) throw new Error(`Failed to load stats: ${response.status}`);
    const data = await response.json();

    // Directly set values
    document.getElementById('playerName').textContent = data.name;
    document.getElementById('playerElo').textContent = `ELO: ${data.skill.toFixed(0)}`;
    document.getElementById('playerProfilePic').src = data.profile_picture;
    
    // Add these new stat updates
    document.getElementById('statKills').textContent = data.kills;
    document.getElementById('statDeaths').textContent = data.deaths;
    document.getElementById('statHS').textContent = data.hs_kills;
    document.getElementById('statAssists').textContent = data.assists;
    document.getElementById('statRevenges').textContent = data.revenges;
    document.getElementById('statTeamKills').textContent = data.team_kills || 0;
    document.getElementById('statDamage').textContent = data.damage;

    // Calculate accuracy
    const accuracy = ((data.hits / data.shots) * 100 || 0).toFixed(1);
    document.getElementById('statAccuracy').textContent = `${accuracy}%`;

    // Match stats
    document.getElementById('statRounds').textContent = data.rounds;
    document.getElementById('statCTWins').textContent = data.wins_ct;
    document.getElementById('statTWins').textContent = data.wins_t;
    document.getElementById('statPlanted').textContent = data.planted;
    document.getElementById('statDefused').textContent = data.defused;

    // Format time played
    const hoursPlayed = Math.floor(data.time / 3600);
    document.getElementById('statTime').textContent = `${hoursPlayed}h`;
    
    // Format weapon names for display
    const formatWeaponName = (weaponKey) => {
      const weaponMap = {
        weapon_ak47: 'AK-47',
        weapon_m4a1: 'M4A1',
        weapon_awp: 'AWP',
        weapon_deagle: 'Desert Eagle',
        weapon_glock18: 'Glock 18',
        weapon_usp: 'USP',
        weapon_hegrenade: 'HE Grenade',
        weapon_knife: 'Knife',
        weapon_fiveseven: 'Five-Seven',
        weapon_elite: 'Dual Berettas',
        weapon_m249: 'M249',
        weapon_galil: 'Galil',
        weapon_famas: 'FAMAS'
      };
      return weaponMap[weaponKey] || weaponKey.replace('weapon_', '').toUpperCase();
    };
    
    // Populate weapon stats
    const weaponsGrid = document.getElementById('weaponsGrid');
    weaponsGrid.innerHTML = data.weapons.map(weapon => `
      <div class="stat-group" style="padding: 10px; margin: 5px 0;">
        <div class="stat-row" style="padding: 5px 0;">
          <span class="stat-label">${formatWeaponName(weapon.weapon)} Kills</span>
          <span class="stat-value">${weapon.kills}</span>
        </div>
        <div class="stat-row" style="padding: 5px 0;">
          <span class="stat-label">Headshots</span>
          <span class="stat-value">${weapon.hs_kills}</span>
        </div>
        <div class="stat-row" style="padding: 5px 0;">
          <span class="stat-label">Damage</span>
          <span class="stat-value">${weapon.damage}</span>
        </div>
      </div>
    `).join('');
  } catch (error) {
    console.error('Stats load error:', error);
    const statsContent = document.querySelector('.stats-content');
    if (statsContent) {
        statsContent.innerHTML = `
          <div class="error-message" style="color: red; padding: 20px;">
            ${error.message}<br>
            <small>If this persists, check if your account has played any matches</small>
          </div>
        `;
    }
  } finally {
    const spinner = document.querySelector('.loading-spinner');
    if(spinner) spinner.style.display = 'none';
  }
}

function initAccordions() {
  document.querySelectorAll('.vgui-title').forEach(title => {
    title.addEventListener('click', function() {
      const panel = this.closest('.vgui-panel');
      panel.classList.toggle('collapsed');
    });
  });
}

// Run page-specific logic
const urlParams = new URLSearchParams(window.location.search);
const playerId = urlParams.get('id') || 'me';
loadPlayerStats(playerId);
initAccordions();
