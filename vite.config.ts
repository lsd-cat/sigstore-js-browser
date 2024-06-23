import { defineConfig } from 'vite';
import { viteSingleFile } from 'vite-plugin-singlefile';
import { configDefaults } from 'vitest/config';

export default defineConfig({
  build: {
    target: 'esnext'
  },
  plugins: [viteSingleFile()],
  test: {
    globals: true,
    include: ['**/__tests__/**/*.test.ts'], // Adjust this pattern as needed
  },
});
