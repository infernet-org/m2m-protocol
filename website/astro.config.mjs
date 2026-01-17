import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://m2m.infernet.org',
  integrations: [
    starlight({
      title: 'M2M',
      description:
        'High-performance Machine-to-Machine protocol for LLM API communication',
      social: {
        github: 'https://github.com/infernet-org/m2m-protocol',
      },
      customCss: ['./src/styles/custom.css'],
      sidebar: [
        {
          label: 'Getting Started',
          autogenerate: { directory: 'guides' },
        },
        {
          label: 'Protocol Specification',
          autogenerate: { directory: 'spec' },
        },
        {
          label: 'Reference',
          autogenerate: { directory: 'reference' },
        },
        {
          label: 'Examples',
          autogenerate: { directory: 'examples/wire-format' },
        },
      ],
      editLink: {
        baseUrl: 'https://github.com/infernet-org/m2m-protocol/edit/main/docs/',
      },
    }),
  ],
});
