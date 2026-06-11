<template>
  <div class="slide-page-number">
    {{ $page }}/{{ $nav.total }}
  </div>
</template>

<style scoped>
.slide-page-number {
  position: absolute;
  left: 50%;
  bottom: 1.15rem;
  transform: translateX(-50%);
  z-index: 20;
  font-size: 0.72rem;
  line-height: 1;
  letter-spacing: 0;
  color: rgba(255, 255, 255, 0.45);
  font-variant-numeric: tabular-nums;
  pointer-events: none;
}
</style>
