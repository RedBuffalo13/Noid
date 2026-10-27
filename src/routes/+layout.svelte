<script lang="ts">
  import "../app.css";
  let { children } = $props();
</script>

<!-- id="app" activates the phone-frame rules in app.css (FE-02): centered
     480px shell + 92vh height on desktop, safe-area insets on mobile. -->
<main id="app">
  {@render children()}
</main>
