// Web Components entry point
import AllumetteAuthComponent from './components/AllumetteAuth.svelte';
import AllumetteFriendsListComponent from './components/AllumetteFriendsList.svelte';
import AllumetteLobbiesComponent from './components/AllumetteLobbies.svelte';


// Register as custom element
if (!customElements.get('allumette-auth')) {
    customElements.define('allumette-auth', AllumetteAuthComponent);
}
if (!customElements.get('allumette-friends-list')) {
    customElements.define('allumette-friends-list', AllumetteFriendsListComponent);
}
if (!customElements.get('allumette-lobbies')) {
    customElements.define('allumette-lobbies', AllumetteLobbiesComponent);
}


// Export the component for direct use if needed
export { AllumetteAuthComponent, AllumetteFriendsListComponent, AllumetteLobbiesComponent };

// Also export the service functions for programmatic use
export * from './allumette-service.js';
