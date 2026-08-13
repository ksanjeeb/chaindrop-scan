#!/usr/bin/env node
'use strict';

/**
 * chaindrop-scan — single-file detector for npm packages compromised by the
 * ChainDrop worm, including transitive dependencies.
 *
 *   node index.js [path] [--json] [--fail-on critical|warning|none] [--quiet]
 *
 * No dependencies, no network, nothing written. Exit 1 if anything is found.
 */

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');

// ---------------------------------------------------------------------------
// Advisory database: package name -> compromised versions
// ---------------------------------------------------------------------------
const ADVISORY = {
 id: "CHAINDROP-2026",
 versionCount: 1674,
 packages: {
  "@adminide-stack/clock-tik-browser": ["12.0.24"],
  "@adminide-stack/yantra-mobile": ["12.0.33"],
  "@arv-bedrock/auth": ["1.1.7", "1.1.8"],
  "@arv-bedrock/auth-admin": ["1.0.2", "1.0.3"],
  "@arv-bedrock/auth-sso": ["1.6.1", "1.6.2"],
  "@arv-bedrock/auth-sso-backend": ["1.7.1", "1.7.2"],
  "@arv-bedrock/logger": ["1.7.1", "1.7.2"],
  "@cacheable/memory": ["2.2.1"],
  "@cacheable/net": ["2.1.1"],
  "@cacheable/node-cache": ["3.1.2"],
  "@cacheable/utils": ["2.5.1"],
  "@deliveroo/determinator": ["0.2.1"],
  "@deliveroo/reevent": ["1.0.1"],
  "@ethlete/cdk": ["4.71.2"],
  "@ethlete/cli": ["2.0.1"],
  "@ethlete/components": ["3.3.1"],
  "@ethlete/contentful": ["3.9.1"],
  "@ethlete/core": ["4.31.1"],
  "@ethlete/dsp": ["0.3.1"],
  "@ethlete/query": ["5.43.2"],
  "@ethlete/theming": ["2.7.1"],
  "@ethlete/types": ["1.11.4"],
  "@forjacms/analytics": ["1.8.4", "1.8.5"],
  "@forjacms/client": ["1.8.4", "1.8.5"],
  "@forjacms/sections": ["1.8.4", "1.8.5"],
  "@forjacms/sections-react": ["1.8.4", "1.8.5"],
  "@hubsync/web-sdk-react": ["6.3.7", "6.3.8", "6.3.9", "6.3.10", "6.3.11", "6.3.12", "6.3.13", "6.3.14", "6.3.15", "6.3.16", "6.3.17", "6.3.18", "6.3.19", "6.3.20", "6.3.21", "6.3.22", "6.3.23", "6.3.24", "6.3.25", "6.3.26", "6.3.27", "6.3.28", "6.3.29", "6.3.30", "6.3.31", "6.3.32", "6.3.33"],
  "@nebula.js/cli": ["7.1.2"],
  "@nebula.js/cli-build": ["7.1.2"],
  "@nebula.js/cli-sense": ["7.1.2"],
  "@nebula.js/cli-serve": ["7.1.2"],
  "@nebula.js/locale": ["0.6.2"],
  "@nebula.js/nucleus": ["0.5.1"],
  "@nebula.js/sn-action-button": ["2.3.1"],
  "@nebula.js/sn-animator": ["2.13.1"],
  "@nebula.js/sn-distributionplot": ["1.0.7"],
  "@nebula.js/sn-layout-container": ["4.4.1"],
  "@nebula.js/sn-line-chart": ["2.7.1"],
  "@nebula.js/sn-listbox": ["0.19.3"],
  "@nebula.js/sn-map": ["0.12.7"],
  "@nebula.js/sn-nav-menu": ["0.14.2"],
  "@nebula.js/sn-org-chart": ["1.7.1"],
  "@nebula.js/sn-shape": ["1.5.1"],
  "@nebula.js/sn-slider": ["0.20.1"],
  "@nebula.js/sn-tabbed-container": ["2.4.1"],
  "@nebula.js/snapshooter": ["0.6.1"],
  "@nebula.js/stardust": ["7.1.2"],
  "@nebula.js/test-utils": ["0.6.1"],
  "@nebula.js/theme": ["0.6.1"],
  "@onereach/authorizer-helper": ["0.0.11", "0.0.12"],
  "@onereach/bandwidth-steps-voice-bxml": ["0.1.1", "0.1.2"],
  "@onereach/billing-dto": ["27.2.1", "27.2.2"],
  "@onereach/billing-shared": ["27.2.1", "27.2.2"],
  "@onereach/cb-schema-translator": ["1.3.1", "1.3.2"],
  "@onereach/channel-transformer": ["0.0.66", "0.0.67"],
  "@onereach/channel-transformers": ["0.0.5", "0.0.6"],
  "@onereach/ckeditor5-build-classic": ["30.0.1", "30.0.2"],
  "@onereach/condition-builder": ["1.0.8", "1.0.9"],
  "@onereach/content-builder": ["0.0.18", "0.0.19"],
  "@onereach/content-builder-template-compiler": ["0.0.3", "0.0.4"],
  "@onereach/expression-components": ["9.1.1", "9.1.2"],
  "@onereach/font-icons": ["27.0.2", "27.0.3"],
  "@onereach/get-version-data": ["3.1.2", "3.1.3"],
  "@onereach/idw-apps": ["0.1.3", "0.1.4"],
  "@onereach/idw-contracts": ["0.1.2", "0.1.3"],
  "@onereach/idw-init-account-resources": ["1.0.1", "1.0.2"],
  "@onereach/idw-sdk": ["0.1.2", "0.1.3"],
  "@onereach/idw-ui-components": ["0.1.2", "0.1.3"],
  "@onereach/lambda-invocation": ["1.2.1", "1.2.2"],
  "@onereach/messengers-infobip-sdk": ["0.1.1", "0.1.2"],
  "@onereach/or-browser": ["0.0.48", "0.0.49"],
  "@onereach/or-browser-next": ["0.0.11", "0.0.12"],
  "@onereach/or-content-builder-renderer": ["0.0.2", "0.0.3"],
  "@onereach/or-file-uploader-next": ["0.0.8", "0.0.9"],
  "@onereach/or-pro": ["1.13.1", "1.13.2"],
  "@onereach/or-sdk-agent-cli": ["0.0.6", "0.0.7"],
  "@onereach/orest-cli": ["2.4.1", "2.4.2"],
  "@onereach/orest-input-cli": ["1.18.1", "1.18.2"],
  "@onereach/orest-jest-presets": ["0.0.3", "0.0.4"],
  "@onereach/orest-vue-demi-vue2": ["0.0.4", "0.0.5"],
  "@onereach/orest-vue-demi-vue3": ["0.0.4", "0.0.5"],
  "@onereach/orest-vue3": ["0.0.4", "0.0.5"],
  "@onereach/phonenumber-interpreter": ["0.0.18", "0.0.19"],
  "@onereach/pnpm-audit-junit": ["1.0.3"],
  "@onereach/postcss-scoped-selector": ["1.2.1", "1.2.2"],
  "@onereach/regex-helper": ["0.5.16", "0.5.17"],
  "@onereach/regular-expressions": ["0.5.23", "0.5.24"],
  "@onereach/regular-expressions-test": ["0.0.4", "0.0.5"],
  "@onereach/rwc-client": ["6.4.7", "6.4.8"],
  "@onereach/salesforce-miaw-client": ["0.0.3", "0.0.4", "0.0.5"],
  "@onereach/si-a-button": ["0.0.3", "0.0.4"],
  "@onereach/si-alert": ["0.4.11", "0.4.12"],
  "@onereach/si-checkbox": ["0.6.5", "0.6.6"],
  "@onereach/si-checkbox-group": ["0.3.5", "0.3.6"],
  "@onereach/si-code": ["0.6.4", "0.6.5"],
  "@onereach/si-collapsible-group": ["0.6.4", "0.6.5"],
  "@onereach/si-copyable-text": ["0.4.11", "0.4.12"],
  "@onereach/si-datepicker": ["0.4.5", "0.4.6"],
  "@onereach/si-divider": ["0.4.11"],
  "@onereach/si-dropdown-advanced": ["0.4.5", "0.4.6"],
  "@onereach/si-dropdown-simple": ["0.4.5", "0.4.6"],
  "@onereach/si-header": ["0.4.11", "0.4.12", "0.4.13"],
  "@onereach/si-list": ["0.7.4"],
  "@onereach/si-merge-tag-input": ["0.4.5"],
  "@onereach/si-radio-group": ["0.3.5", "0.3.6"],
  "@onereach/si-root": ["0.9.4", "0.9.5"],
  "@onereach/si-select": ["0.1.3", "0.1.4"],
  "@onereach/si-step-chooser": ["0.4.4", "0.4.5"],
  "@onereach/si-switch": ["0.4.5", "0.4.6"],
  "@onereach/si-text-message": ["0.4.5", "0.4.6"],
  "@onereach/si-textinput": ["0.5.5", "0.5.6"],
  "@onereach/si-validated-timestring-input": ["0.3.5", "0.3.6"],
  "@onereach/slack-helpers": ["1.0.3", "1.0.4"],
  "@onereach/ssml-editor": ["2.0.12", "2.0.13"],
  "@onereach/step-components": ["0.1.37"],
  "@onereach/step-conversation": ["1.0.41", "1.0.42"],
  "@onereach/step-run-snowflake-query": ["0.1.1", "0.1.2"],
  "@onereach/step-voice": ["7.0.32", "7.0.33"],
  "@onereach/styles": ["27.0.2", "27.0.3"],
  "@onereach/time-interpreter": ["1.0.30", "1.0.31"],
  "@onereach/ts-memoize": ["1.0.2", "1.0.3"],
  "@onereach/types-contacts-api": ["9.0.8", "9.0.9"],
  "@onereach/ui-components": ["27.0.2", "27.0.3"],
  "@onereach/ui-components-common": ["27.0.2", "27.0.3"],
  "@onereach/ui-components-vue2": ["27.0.2", "27.0.3"],
  "@onereach/v-event-calendar": ["0.1.22", "0.1.23"],
  "@onereach/webform": ["0.3.13", "0.3.14"],
  "@or-sdk/account-settings": ["1.3.6", "1.3.7"],
  "@or-sdk/accounts": ["2.3.5"],
  "@or-sdk/adapters": ["0.3.6", "0.3.7"],
  "@or-sdk/agents": ["4.21.3", "4.21.4"],
  "@or-sdk/api-tokens": ["1.4.2", "1.4.3"],
  "@or-sdk/api-tokens-lambda": ["1.4.2"],
  "@or-sdk/apps": ["1.2.6", "1.2.7"],
  "@or-sdk/auth": ["0.38.1", "0.38.2"],
  "@or-sdk/authorizer": ["0.26.7", "0.26.8"],
  "@or-sdk/base": ["0.44.4", "0.44.5"],
  "@or-sdk/billing": ["27.2.1", "27.2.2"],
  "@or-sdk/billing-internal": ["27.2.1", "27.2.2"],
  "@or-sdk/bot-templates": ["2.2.5", "2.2.6"],
  "@or-sdk/bots": ["1.7.1", "1.7.2"],
  "@or-sdk/card-templates": ["2.2.5", "2.2.6"],
  "@or-sdk/cards": ["1.2.5", "1.2.6"],
  "@or-sdk/ccp": ["10.15.4", "10.15.5"],
  "@or-sdk/chat": ["0.3.1"],
  "@or-sdk/contacts": ["4.7.5", "4.7.6"],
  "@or-sdk/content-request": ["0.2.6", "0.2.7"],
  "@or-sdk/data-hub": ["0.26.5", "0.26.6"],
  "@or-sdk/data-hub-svc": ["2.3.5", "2.3.6"],
  "@or-sdk/deployer": ["1.7.5", "1.7.6"],
  "@or-sdk/deployments": ["2.1.5", "2.1.6"],
  "@or-sdk/discovery": ["1.12.1", "1.12.2"],
  "@or-sdk/druid": ["1.4.7", "1.4.8"],
  "@or-sdk/event-manager": ["1.1.5", "1.1.6"],
  "@or-sdk/files": ["3.11.6", "3.11.7"],
  "@or-sdk/files-sync-node": ["0.1.8", "0.1.9"],
  "@or-sdk/flow-templates": ["2.1.5", "2.1.6"],
  "@or-sdk/flows": ["2.7.8", "2.7.9"],
  "@or-sdk/graph": ["1.10.5", "1.10.6"],
  "@or-sdk/hitl": ["0.41.1", "0.41.2"],
  "@or-sdk/identifiers": ["0.27.6", "0.27.7"],
  "@or-sdk/idw": ["9.0.4", "9.0.5"],
  "@or-sdk/idw-public": ["1.6.6", "1.6.7"],
  "@or-sdk/idw-skill": ["1.4.1", "1.4.2"],
  "@or-sdk/invitations": ["1.4.8", "1.4.9"],
  "@or-sdk/key-value-storage": ["0.28.6", "0.28.7"],
  "@or-sdk/keys": ["1.2.6", "1.2.7"],
  "@or-sdk/knowledge-models": ["0.25.5", "0.25.6"],
  "@or-sdk/library": ["0.5.6", "0.5.7"],
  "@or-sdk/library-categories": ["0.2.6", "0.2.7"],
  "@or-sdk/library-source": ["0.4.5", "0.4.6"],
  "@or-sdk/library-types-v1": ["9.0.1", "9.0.2"],
  "@or-sdk/library-types-v2": ["9.0.1", "9.0.2"],
  "@or-sdk/lookup": ["1.25.1", "1.25.2"],
  "@or-sdk/markdowner": ["0.5.1", "0.5.2"],
  "@or-sdk/mcp-tools": ["0.5.2", "0.5.3"],
  "@or-sdk/notifications": ["1.7.5", "1.7.6"],
  "@or-sdk/password": ["1.3.6", "1.3.7"],
  "@or-sdk/payments": ["3.2.5", "3.2.6"],
  "@or-sdk/permissions": ["2.8.1", "2.8.2"],
  "@or-sdk/permissions-cli": ["1.4.1", "1.4.2"],
  "@or-sdk/permissions-lambda": ["2.5.1", "2.5.2"],
  "@or-sdk/pgsql": ["1.5.1", "1.5.2"],
  "@or-sdk/providers": ["0.3.6", "0.3.7"],
  "@or-sdk/qna": ["3.4.2", "3.4.3"],
  "@or-sdk/queue-manager": ["1.4.6", "1.4.7"],
  "@or-sdk/sdk-api": ["0.29.2", "0.29.3"],
  "@or-sdk/settings": ["0.25.6", "0.25.7"],
  "@or-sdk/sku-builder": ["2.5.1", "2.5.2"],
  "@or-sdk/source": ["2.1.5", "2.1.6"],
  "@or-sdk/source-api": ["1.1.1", "1.1.2"],
  "@or-sdk/step-templates": ["2.2.5", "2.2.6"],
  "@or-sdk/store": ["2.1.5", "2.1.6"],
  "@or-sdk/tables": ["0.28.5", "0.28.6"],
  "@or-sdk/tags": ["1.1.5", "1.1.6"],
  "@or-sdk/tickets": ["1.9.5", "1.9.6"],
  "@or-sdk/transcripts": ["1.2.5", "1.2.6"],
  "@or-sdk/users": ["3.8.1", "3.8.2"],
  "@or-sdk/view-templates": ["2.2.5", "2.2.6"],
  "@or-sdk/views": ["3.1.5", "3.1.6"],
  "@or-sdk/web-search": ["0.6.1", "0.6.2"],
  "@ornikar/apollo-link-timeout": ["1.4.2", "1.4.3", "1.4.4", "1.4.5", "1.4.6"],
  "@ornikar/babel-preset-base": ["6.0.3", "6.0.4", "6.0.5", "6.0.6", "6.0.7", "6.0.8", "6.0.9", "6.0.10"],
  "@ornikar/babel-preset-kitt-universal": ["8.0.3", "8.0.4", "8.0.5", "8.0.6", "8.0.7", "8.0.8"],
  "@ornikar/babel-preset-react": ["6.1.4", "6.1.5", "6.1.6", "6.1.7", "6.1.8", "6.1.9", "6.1.10"],
  "@ornikar/browserslist-config": ["8.0.3", "8.0.4", "8.0.5", "8.0.6", "8.0.7", "8.0.8", "8.0.9"],
  "@ornikar/commitlint-config": ["8.3.2", "8.3.3", "8.3.4", "8.3.5", "8.3.6", "8.3.7", "8.3.8"],
  "@ornikar/eslint-config": ["24.0.1", "24.0.2", "24.0.3", "24.0.4", "24.0.5", "24.0.6", "24.0.7", "24.0.8"],
  "@ornikar/eslint-config-babel": ["24.0.1", "24.0.2", "24.0.3", "24.0.4", "24.0.5", "24.0.6", "24.0.7", "24.0.8"],
  "@ornikar/eslint-config-babel-use": ["13.2.1", "13.2.2", "13.2.3", "13.2.4", "13.2.5", "13.2.6", "13.2.7", "13.2.8"],
  "@ornikar/eslint-config-formatjs": ["24.0.1", "24.0.2", "24.0.3", "24.0.4", "24.0.5", "24.0.6"],
  "@ornikar/eslint-config-node": ["12.2.1", "12.2.2", "12.2.3", "12.2.4", "12.2.5", "12.2.6"],
  "@ornikar/eslint-config-react": ["24.0.1", "24.0.2", "24.0.3", "24.0.4", "24.0.5", "24.0.6", "24.0.7"],
  "@ornikar/eslint-config-typescript": ["24.0.1", "24.0.2", "24.0.3", "24.0.4", "24.0.5", "24.0.6"],
  "@ornikar/eslint-config-typescript-nestjs": ["24.0.1", "24.0.2", "24.0.3", "24.0.4", "24.0.5", "24.0.6", "24.0.7"],
  "@ornikar/eslint-config-typescript-react": ["24.0.1", "24.0.2", "24.0.3", "24.0.4", "24.0.5", "24.0.6", "24.0.7"],
  "@ornikar/eslint-plugin-neverthrow": ["1.3.1", "1.3.2", "1.3.3", "1.3.4", "1.3.5", "1.3.6", "1.3.7", "1.3.8"],
  "@ornikar/eslint-plugin-ornikar": ["24.0.1", "24.0.2", "24.0.3", "24.0.4", "24.0.5", "24.0.6", "24.0.7"],
  "@ornikar/graphql-config": ["1.1.1", "1.1.2", "1.1.3", "1.1.4", "1.1.5", "1.1.6", "1.1.7"],
  "@ornikar/intl-config": ["10.0.2", "10.0.3", "10.0.4", "10.0.5", "10.0.6", "10.0.7", "10.0.8"],
  "@ornikar/jest-config": ["13.0.3", "13.0.4", "13.0.5", "13.0.6", "13.0.7", "13.0.8", "13.0.9"],
  "@ornikar/jest-config-react": ["18.0.2", "18.0.3", "18.0.4", "18.0.5", "18.0.6", "18.0.7", "18.0.8"],
  "@ornikar/jest-config-react-native": ["17.0.2", "17.0.3", "17.0.4", "17.0.5", "17.0.6", "17.0.7", "17.0.8"],
  "@ornikar/jest-config-react-native-web": ["12.0.3", "12.0.4", "12.0.5", "12.0.6", "12.0.7", "12.0.8", "12.0.9"],
  "@ornikar/kitt2": ["1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7"],
  "@ornikar/lerna-config": ["11.0.1", "11.0.2", "11.0.3", "11.0.4", "11.0.5", "11.0.6"],
  "@ornikar/monorepo-config": ["14.3.2", "14.3.3", "14.3.4", "14.3.5", "14.3.6", "14.3.7", "14.3.8", "14.3.9"],
  "@ornikar/postcss-config": ["9.1.2", "9.1.3", "9.1.4", "9.1.5", "9.1.6", "9.1.7", "9.1.8"],
  "@ornikar/prettier-config": ["9.0.3", "9.0.4", "9.0.5", "9.0.6", "9.0.7", "9.0.8", "9.0.9"],
  "@ornikar/prismic-components": ["0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6", "0.0.7", "0.0.8"],
  "@ornikar/react-modern-calendar-datepicker": ["3.2.1", "3.2.2", "3.2.3", "3.2.4", "3.2.5", "3.2.6", "3.2.7"],
  "@ornikar/react-native-svg-transformer": ["1.0.6", "1.0.7", "1.0.8", "1.0.9", "1.0.10", "1.0.11"],
  "@ornikar/renovate-config": ["9.0.2", "9.0.3", "9.0.4", "9.0.5", "9.0.6", "9.0.7", "9.0.8", "9.0.9"],
  "@ornikar/repo-config": ["15.3.3", "15.3.4", "15.3.5", "15.3.6", "15.3.7", "15.3.8", "15.3.9"],
  "@ornikar/repo-config-react": ["13.0.8", "13.0.9", "13.0.10", "13.0.11", "13.0.12", "13.0.13", "13.0.14", "13.0.15"],
  "@ornikar/repo-config-react-legacy-css": ["15.1.2", "15.1.3", "15.1.4", "15.1.5", "15.1.6", "15.1.7", "15.1.8", "15.1.9"],
  "@ornikar/rollup-config": ["11.1.2", "11.1.3", "11.1.4", "11.1.5", "11.1.6", "11.1.7", "11.1.8", "11.1.9"],
  "@ornikar/rollup-plugin-postcss": ["2.0.5", "2.0.6", "2.0.7", "2.0.8", "2.0.9", "2.0.10", "2.0.11"],
  "@ornikar/slate-react-fork": ["1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7"],
  "@ornikar/storybook-config": ["12.1.2", "12.1.3", "12.1.4", "12.1.5", "12.1.6", "12.1.7"],
  "@ornikar/stylelint-config": ["14.0.3", "14.0.5", "14.0.6", "14.0.7", "14.0.8", "14.0.9"],
  "@ornikar/typed-css-modules-loader": ["0.8.2", "0.8.3", "0.8.4", "0.8.5", "0.8.6", "0.8.7", "0.8.8"],
  "@ornikar/webpack-config": ["12.0.2", "12.0.3", "12.0.4", "12.0.5", "12.0.6", "12.0.7", "12.0.8"],
  "@picsart/ai-sdk": ["3.32.2"],
  "@picsart/gen-ai": ["2.55.11"],
  "@qlik/api": ["2.14.2"],
  "@qlik/browserslist-config": ["3.0.2"],
  "@qlik/carbon-core": ["2.1.1"],
  "@qlik/carboncopy": ["1.1.6"],
  "@qlik/design-tokens": ["1.3.13"],
  "@qlik/dts-bundler": ["2.0.3"],
  "@qlik/embed-react": ["2.5.3"],
  "@qlik/embed-runtime": ["1.6.4"],
  "@qlik/embed-svelte": ["1.1.4"],
  "@qlik/embed-web-components": ["1.7.3"],
  "@qlik/eslint-config": ["2.0.20"],
  "@qlik/eslint-config-base": ["0.1.1"],
  "@qlik/eslint-config-react": ["0.1.1"],
  "@qlik/eslint-config-svelte": ["0.1.1"],
  "@qlik/eslint-config-vue": ["0.1.1"],
  "@qlik/nebula-table-utils": ["2.6.9"],
  "@qlik/oxfmt-config": ["0.1.6"],
  "@qlik/oxlint-config": ["0.7.2"],
  "@qlik/prettier-config": ["1.0.3"],
  "@qlik/react-native-simple-grid": ["1.5.5"],
  "@qlik/runtime-module-loader": ["1.5.1"],
  "@qlik/sdk": ["0.28.1"],
  "@qlik/sprout-design-docs": ["1.0.2"],
  "@qlik/sprout-gesture": ["0.0.13"],
  "@qlik/sprout-icons": ["0.12.3"],
  "@qlik/sprout-react": ["6.45.3"],
  "@qlik/sprout-react-table": ["0.16.7"],
  "@qlik/tsconfig": ["1.0.3"],
  "@redhat-cloud-services/compliance-client": ["4.0.4"],
  "@redhat-cloud-services/frontend-components-config-utilities": ["4.11.3"],
  "@redhat-cloud-services/frontend-components-utilities": ["7.4.2"],
  "@redhat-cloud-services/insights-client": ["4.0.4"],
  "@redhat-cloud-services/rbac-client": ["9.0.6"],
  "@redhat-cloud-services/sources-client": ["3.0.10"],
  "@redhat-cloud-services/types": ["3.6.1"],
  "@servicetitan/acquisition-functions": ["5.22.1", "5.22.2", "5.22.3", "5.22.4", "5.22.5"],
  "@servicetitan/admin-layout": ["2.4.3", "2.4.4", "2.4.5", "2.4.6", "2.4.7"],
  "@servicetitan/admin-sql-table": ["1.0.14", "1.0.15", "1.0.16", "1.0.17", "1.0.18"],
  "@servicetitan/ajax-handlers": ["38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5"],
  "@servicetitan/anvil-css-utilities": ["14.5.4", "14.5.5", "14.5.6", "14.5.7", "14.5.8"],
  "@servicetitan/anvil-fonts": ["14.5.4", "14.5.5", "14.5.6", "14.5.7", "14.5.8"],
  "@servicetitan/anvil-icon": ["0.5.1", "0.5.2", "0.5.3", "0.5.4", "0.5.5"],
  "@servicetitan/anvil-icons": ["14.5.4", "14.5.5", "14.5.6", "14.5.7", "14.5.8"],
  "@servicetitan/anvil-react": ["0.11.3", "0.11.4", "0.11.5", "0.11.6", "0.11.7"],
  "@servicetitan/anvil-themes": ["14.5.4", "14.5.5", "14.5.6", "14.5.7", "14.5.8"],
  "@servicetitan/anvil-token": ["0.4.1", "0.4.2", "0.4.3", "0.4.4", "0.4.5"],
  "@servicetitan/anvil2": ["3.9.1", "3.9.2", "3.9.3", "3.9.4", "3.9.5"],
  "@servicetitan/anvil2-codemods": ["0.11.2", "0.11.3", "0.11.4", "0.11.5", "0.11.6"],
  "@servicetitan/anvil2-ext-atlas": ["4.0.2", "4.0.3", "4.0.4", "4.0.5", "4.0.6"],
  "@servicetitan/anvil2-ext-charts": ["0.2.4", "0.2.5", "0.2.6", "0.2.7", "0.2.8"],
  "@servicetitan/anvil2-ext-common": ["0.7.1", "0.7.2", "0.7.3", "0.7.4", "0.7.5"],
  "@servicetitan/anvil2-ext-mwv": ["0.0.5", "0.0.6", "0.0.7", "0.0.8", "0.0.9"],
  "@servicetitan/anvil2-illustrations": ["1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6"],
  "@servicetitan/anvil2-mcp": ["0.0.9", "0.0.10", "0.0.11", "0.0.12", "0.0.13"],
  "@servicetitan/assist-ui": ["2.1.1", "2.1.2", "2.1.3", "2.1.4", "2.1.5"],
  "@servicetitan/assist-utils": ["1.1.2", "1.1.3", "1.1.4", "1.1.5", "1.1.6"],
  "@servicetitan/carto-charts-core": ["0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6"],
  "@servicetitan/carto-charts-react": ["0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6"],
  "@servicetitan/carto-charts-rn": ["0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6"],
  "@servicetitan/carto-react-kit": ["0.8.4", "0.8.5", "0.8.6", "0.8.7", "0.8.8"],
  "@servicetitan/carto-rn-kit": ["0.0.10", "0.0.11", "0.0.12", "0.0.13", "0.0.14"],
  "@servicetitan/carto-tokens": ["0.3.1", "0.3.2", "0.3.3", "0.3.4", "0.3.5"],
  "@servicetitan/component-usage": ["28.5.1", "28.5.2", "28.5.3", "28.5.4", "28.5.5"],
  "@servicetitan/confirm": ["41.3.1", "41.3.2", "41.3.3", "41.3.4", "41.3.5"],
  "@servicetitan/confirm-navigation": ["41.3.1", "41.3.2", "41.3.3", "41.3.4", "41.3.5"],
  "@servicetitan/contentful": ["0.0.3", "0.0.4", "0.0.5", "0.0.6", "0.0.7"],
  "@servicetitan/contentful-proxy": ["1.1.12", "1.1.13", "1.1.14", "1.1.15", "1.1.16"],
  "@servicetitan/cp-api": ["1.115.1", "1.115.2", "1.115.3", "1.115.4", "1.115.5"],
  "@servicetitan/cp-mfe": ["1.115.1", "1.115.2", "1.115.3", "1.115.4", "1.115.5"],
  "@servicetitan/cp-mfe-dev": ["1.115.1", "1.115.2", "1.115.3", "1.115.4", "1.115.5"],
  "@servicetitan/cp-react-hooks": ["1.115.1", "1.115.2", "1.115.3", "1.115.4", "1.115.5"],
  "@servicetitan/cp-ui": ["1.115.1", "1.115.2", "1.115.3", "1.115.4", "1.115.5"],
  "@servicetitan/culture": ["41.3.1", "41.3.2", "41.3.3", "41.3.4", "41.3.5"],
  "@servicetitan/data-query": ["41.3.1", "41.3.2", "41.3.3", "41.3.4", "41.3.5"],
  "@servicetitan/datadog-rum": ["38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5"],
  "@servicetitan/datetime-utils": ["41.3.1", "41.3.2", "41.3.3", "41.3.4", "41.3.5"],
  "@servicetitan/design-system": ["14.5.4", "14.5.5", "14.5.6", "14.5.7", "14.5.8"],
  "@servicetitan/docs-anvil-uikit-contrib": ["41.3.1", "41.3.2", "41.3.3", "41.3.4", "41.3.5"],
  "@servicetitan/docs-uikit": ["38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5"],
  "@servicetitan/document-title": ["2.4.1", "2.4.2", "2.4.3", "2.4.4", "2.4.5"],
  "@servicetitan/dte-pdf-editor": ["1.76.1", "1.76.2", "1.76.3", "1.76.4", "1.76.5"],
  "@servicetitan/dte-unlayer": ["0.150.1", "0.150.2", "0.150.3", "0.150.4", "0.150.5"],
  "@servicetitan/eh-module-communication": ["0.2.1", "0.2.2", "0.2.3", "0.2.4", "0.2.5"],
  "@servicetitan/error-boundary": ["38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5"],
  "@servicetitan/eslint-config": ["38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5"],
  "@servicetitan/eslint-plugin": ["38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5"],
  "@servicetitan/eslint-plugin-decorators-declare": ["12.8.15", "12.8.16", "12.8.17", "12.8.18", "12.8.19"],
  "@servicetitan/eslint-plugin-folder-schema": ["38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5"],
  "@servicetitan/eslint-plugin-mobx-6": ["12.8.15", "12.8.16", "12.8.17", "12.8.18"],
  "@servicetitan/eslint-plugin-processors-stub": ["12.8.15", "12.8.16", "12.8.17", "12.8.18", "12.8.19"],
  "@servicetitan/examples": ["1.2.5", "1.2.6", "1.2.7", "1.2.8", "1.2.9"],
  "@servicetitan/feature-spotlight": ["3.9.1", "3.9.2", "3.9.3", "3.9.4", "3.9.5"],
  "@servicetitan/folder-lint": ["38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5"],
  "@servicetitan/forge": ["0.5.1", "0.5.2", "0.5.3", "0.5.4", "0.5.5"],
  "@servicetitan/form": ["41.3.1", "41.3.2", "41.3.3", "41.3.4", "41.3.5"],
  "@servicetitan/form-state": ["41.3.1", "41.3.2", "41.3.3", "41.3.4", "41.3.5"],
  "@servicetitan/grid": ["0.0.63", "0.0.64", "0.0.65", "0.0.66", "0.0.67"],
  "@servicetitan/hammer-icon": ["1.2.1", "1.2.2", "1.2.3", "1.2.4", "1.2.5"],
  "@servicetitan/hammer-react": ["1.42.2", "1.42.3", "1.42.4", "1.42.5", "1.42.6"],
  "@servicetitan/hammer-token": ["3.1.1", "3.1.2", "3.1.3", "3.1.4", "3.1.5"],
  "@servicetitan/hash-browser-router": ["38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5"],
  "@servicetitan/help-center": ["1.0.8", "1.0.9", "1.0.10", "1.0.11", "1.0.12"],
  "@servicetitan/html-sketchapp": ["4.2.8", "4.2.9", "4.2.10", "4.2.11", "4.2.12"],
  "@servicetitan/install": ["38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5"],
  "@servicetitan/intl": ["7.2.1", "7.2.2", "7.2.3", "7.2.4", "7.2.5"],
  "@servicetitan/json-render-react": ["0.4.6", "0.4.7", "0.4.8", "0.4.9", "0.4.10"],
  "@servicetitan/kendo-theme": ["0.0.27", "0.0.28", "0.0.29", "0.0.30", "0.0.31"],
  "@servicetitan/ko-bridge": ["38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5"],
  "@servicetitan/launchdarkly-service": ["38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5"],
  "@servicetitan/lazy-module": ["38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5"],
  "@servicetitan/ld-type-generator": ["0.2.1", "0.2.2", "0.2.3", "0.2.4", "0.2.5"],
  "@servicetitan/line-item-editor": ["1.5.1", "1.5.2", "1.5.3", "1.5.4", "1.5.5"],
  "@servicetitan/link-item": ["41.3.1", "41.3.2", "41.3.3", "41.3.4", "41.3.5"],
  "@servicetitan/log-service": ["38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5"],
  "@servicetitan/marketing-direct-mail-components": ["20.1.1", "20.1.2", "20.1.3", "20.1.4", "20.1.5"],
  "@servicetitan/marketing-email-components": ["20.2.3", "20.2.4", "20.2.5", "20.2.6", "20.2.7"],
  "@servicetitan/marketing-form": ["0.1.2", "0.1.3", "0.1.4", "0.1.5", "0.1.6"],
  "@servicetitan/marketing-global-route": ["1.14.1", "1.14.2", "1.14.3", "1.14.4", "1.14.5"],
  "@servicetitan/marketing-integration-widgets": ["1.0.40", "1.0.41", "1.0.42", "1.0.43", "1.0.44"],
  "@servicetitan/marketing-route": ["1.2.1", "1.2.2", "1.2.3", "1.2.4", "1.2.5"],
  "@servicetitan/marketing-ui": ["9.3.1", "9.3.2", "9.3.3", "9.3.4", "9.3.5"],
  "@servicetitan/marketing-widgets": ["1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5"],
  "@servicetitan/measure-sheet-data": ["2.6.1", "2.6.2", "2.6.3", "2.6.4", "2.6.5"],
  "@servicetitan/mfe-quick-actions": ["0.5.49", "0.5.50", "0.5.51", "0.5.52", "0.5.53"],
  "@servicetitan/micro-frontend": ["0.0.4", "0.0.5", "0.0.6", "0.0.7", "0.0.8"],
  "@servicetitan/microfront": ["0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6"],
  "@servicetitan/microfront-auth": ["0.0.5", "0.0.6", "0.0.7", "0.0.8", "0.0.9"],
  "@servicetitan/microfront-tests": ["0.0.11", "0.0.12", "0.0.13", "0.0.14", "0.0.15"],
  "@servicetitan/microfront-utils": ["1.4.1", "1.4.2", "1.4.3", "1.4.4", "1.4.5"],
  "@servicetitan/modularpayments-webfields": ["1.0.53", "1.0.54", "1.0.55", "1.0.56", "1.0.57"],
  "@servicetitan/moneyout-api-client": ["1.29.1", "1.29.2", "1.29.3", "1.29.4", "1.29.5"],
  "@servicetitan/mpa-components": ["2.5.1", "2.5.2", "2.5.3", "2.5.4", "2.5.5"],
  "@servicetitan/navigation": ["14.1.1", "14.1.2", "14.1.3", "14.1.4", "14.1.5"],
  "@servicetitan/notifications": ["41.3.1", "41.3.2", "41.3.3", "41.3.4", "41.3.5"],
  "@servicetitan/onboarding-ui": ["18.5.1", "18.5.2", "18.5.3", "18.5.4", "18.5.5"],
  "@servicetitan/quick-actions": ["1.15.2", "1.15.3", "1.15.4", "1.15.5", "1.15.6"],
  "@servicetitan/react-hooks": ["7.7.1", "7.7.2", "7.7.3", "7.7.4", "7.7.5"],
  "@servicetitan/react-ioc": ["38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5"],
  "@servicetitan/responsive": ["6.1.1", "6.1.2", "6.1.3", "6.1.4", "6.1.5"],
  "@servicetitan/restrict-imports": ["38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5"],
  "@servicetitan/schema-comparison": ["0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.7"],
  "@servicetitan/skeleton": ["9.2.4", "9.2.5", "9.2.6", "9.2.7", "9.2.8"],
  "@servicetitan/standalone-core-feature-gates": ["1.11.4", "1.11.5", "1.11.6", "1.11.7", "1.11.8"],
  "@servicetitan/standalone-feature-flags": ["2.3.2", "2.3.3", "2.3.4", "2.3.5", "2.3.6"],
  "@servicetitan/standalone-root": ["1.11.3", "1.11.4", "1.11.5", "1.11.6", "1.11.7"],
  "@servicetitan/standalone-tm-api": ["1.1.1", "1.1.2", "1.1.3", "1.1.4", "1.1.5"],
  "@servicetitan/standalone-ui": ["2.2.4", "2.2.5", "2.2.6", "2.2.7", "2.2.8"],
  "@servicetitan/startup": ["38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5"],
  "@servicetitan/startup-jest": ["2.2.1", "2.2.2", "2.2.3", "2.2.4", "2.2.5"],
  "@servicetitan/startup-mfe-compat": ["0.5.1", "0.5.2", "0.5.3", "0.5.4", "0.5.5"],
  "@servicetitan/startup-utils": ["38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5"],
  "@servicetitan/stylelint-config": ["38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5"],
  "@servicetitan/suppress-warnings": ["38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5"],
  "@servicetitan/table": ["41.3.1", "41.3.2", "41.3.3", "41.3.4", "41.3.5"],
  "@servicetitan/tanstack-query-mobx": ["6.2.1", "6.2.2", "6.2.3", "6.2.4", "6.2.5"],
  "@servicetitan/temporal-lite": ["3.4.1", "3.4.2", "3.4.3", "3.4.4", "3.4.5"],
  "@servicetitan/testing-library": ["6.6.1", "6.6.2", "6.6.3", "6.6.4", "6.6.5"],
  "@servicetitan/thoughtspot-theme": ["1.7.1", "1.7.2", "1.7.3", "1.7.4", "1.7.5"],
  "@servicetitan/time-zones": ["3.8.1", "3.8.2", "3.8.3", "3.8.4", "3.8.5"],
  "@servicetitan/titan-chat-ui": ["7.1.3", "7.1.4", "7.1.5", "7.1.6", "7.1.7"],
  "@servicetitan/titan-chat-ui-anvil2": ["9.0.1", "9.0.2", "9.0.3", "9.0.4", "9.0.5"],
  "@servicetitan/titan-chat-ui-common": ["9.0.1", "9.0.2", "9.0.3", "9.0.4", "9.0.5"],
  "@servicetitan/titan-chat-ui-cypress": ["2.1.3", "2.1.4", "2.1.5", "2.1.6", "2.1.7"],
  "@servicetitan/titan-chatbot-api": ["9.0.1", "9.0.2", "9.0.3", "9.0.4", "9.0.5"],
  "@servicetitan/titan-chatbot-client": ["2.1.3", "2.1.4", "2.1.5", "2.1.6", "2.1.7"],
  "@servicetitan/titan-chatbot-ui": ["7.1.3", "7.1.4", "7.1.5", "7.1.6", "7.1.7"],
  "@servicetitan/titan-chatbot-ui-anvil2": ["9.0.1", "9.0.2", "9.0.3", "9.0.4", "9.0.5"],
  "@servicetitan/titan-chatbot-ui-cypress": ["9.0.1", "9.0.2", "9.0.3", "9.0.4", "9.0.5"],
  "@servicetitan/tokens": ["12.9.1", "12.9.2", "12.9.3", "12.9.4", "12.9.5"],
  "@servicetitan/toolbelt-shared-registry": ["1.14.1", "1.14.2", "1.14.3", "1.14.4", "1.14.5"],
  "@servicetitan/uikit-docs": ["22.11.1", "22.11.2", "22.11.3", "22.11.4", "22.11.5"],
  "@servicetitan/unit-tests": ["0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6"],
  "@servicetitan/va-mfe-loader": ["1.1.1", "1.1.2", "1.1.3", "1.1.4", "1.1.5"],
  "@servicetitan/web-components": ["38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5"],
  "@servicetitan/widget-platform": ["5.6.1", "5.6.2", "5.6.3", "5.6.4", "5.6.5"],
  "@servicetitan/widget-platform-monolith": ["5.6.1", "5.6.2", "5.6.3", "5.6.4", "5.6.5"],
  "@squawk/types": ["0.8.1"],
  "@thiennq/docs-viewer": ["1.6.2"],
  "@umacloud/cli-win32-x64": ["1.0.74"],
  "@workbench-stack/core": ["3.9.8"],
  "ai-sdk-ollama": ["0.13.1", "1.1.1", "2.2.1", "3.8.5"],
  "autotel-devtools": ["0.1.1", "4.0.1"],
  "autotel-mcp": ["3.0.1", "15.0.2", "19.0.1", "21.1.1", "24.0.1", "25.0.1", "28.0.3", "29.0.1"],
  "autotel-mcp-instrumentation": ["32.0.1", "33.0.2"],
  "autotel-subscribers": ["16.0.2", "24.0.1", "29.0.6"],
  "autotel-terminal": ["4.0.2", "14.0.1", "15.0.2", "16.0.2"],
  "awaitly-analyze": ["2.0.1", "3.0.1", "6.0.1", "7.0.1"],
  "awaitly-libsql": ["10.0.1", "12.0.1", "20.0.1"],
  "awaitly-mongo": ["2.0.1", "4.0.1", "6.0.1", "12.0.1", "15.0.1", "18.0.1", "21.0.1", "23.0.1"],
  "awaitly-postgres": ["2.0.1", "3.0.2", "5.0.1", "6.0.1", "8.0.1", "13.0.1", "14.0.1", "16.0.1", "21.0.1", "22.0.1"],
  "awaitly-visualizer": ["4.0.1", "10.0.1", "12.0.1", "13.0.1", "18.1.1", "21.0.1"],
  "babel-plugin-linaria-css-to-undefined": ["0.3.1", "0.3.2", "0.3.3", "0.3.4", "0.3.5", "0.3.6", "0.3.7", "0.3.8", "0.3.9"],
  "cache-manager": ["7.2.10"],
  "cacheable": ["2.5.1"],
  "cacheable-request": ["13.0.20"],
  "conv-context-next": ["1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.0.8"],
  "create-cf-token": ["1.1.2", "1.1.3", "1.1.4"],
  "create-wrangler-deploy": ["0.1.1"],
  "creditcard.js": ["2.1.8", "3.0.60"],
  "dbmux": ["1.0.5", "1.0.6", "2.2.5"],
  "discord-search": ["0.1.1", "0.1.2", "0.1.3"],
  "ecto": ["5.0.1"],
  "editable-contracts": ["0.0.12", "0.0.13", "0.0.14", "0.0.15", "0.0.16", "0.0.17", "0.0.18", "0.0.19", "0.0.20", "0.0.21", "0.0.22", "0.0.23", "0.0.24", "0.0.25"],
  "eslint-plugin-executable-stories-playwright": ["2.1.8"],
  "eslint-plugin-folder-schema": ["1.0.6", "1.0.7", "1.0.8", "1.0.9", "1.0.10", "1.0.11", "1.0.12", "1.0.13", "1.0.14", "1.0.15", "1.0.16", "1.0.17", "1.0.18", "1.0.19"],
  "example-js-project": ["1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.8", "1.0.9"],
  "executable-stories-playwright": ["4.0.1", "5.0.1", "6.1.1"],
  "executable-stories-vitest": ["2.0.1", "3.1.1", "5.0.1", "6.1.1"],
  "file-entry-cache": ["11.1.6"],
  "flat-cache": ["6.1.24"],
  "folder-lint": ["1.0.6", "1.0.7", "1.0.8", "1.0.9", "1.0.10", "1.0.11", "1.0.12", "1.0.13", "1.0.14", "1.0.15", "1.0.16", "1.0.17", "1.0.18", "1.0.19"],
  "frontend-orb": ["4.4.1", "4.4.2", "4.4.3", "4.4.4", "4.4.5", "4.4.6", "4.4.7", "4.4.8", "4.4.9", "4.4.10"],
  "github-archiver": ["1.5.4", "1.5.5", "1.5.6"],
  "hamus.js": ["0.4.1"],
  "http-metrics-middleware": ["2.2.2"],
  "intercom-client": ["7.0.4"],
  "keyv": ["6.0.0"],
  "leo-aws": ["2.0.4"],
  "leo-cron": ["2.0.2"],
  "mountly": ["0.2.2"],
  "native-frontend-orb": ["1.1.4", "1.1.5", "1.1.6", "1.1.7", "1.1.8", "1.1.9", "1.1.10", "1.1.11"],
  "picasso-plugin-hammer": ["2.11.6"],
  "picasso-plugin-q": ["2.11.6"],
  "picasso.js": ["2.11.6"],
  "pob-test-package-in-monorepo": ["5.2.1", "5.2.2", "5.2.3", "5.2.4", "5.2.5", "5.2.6", "5.2.7", "5.2.8", "5.2.9"],
  "pob-test-typescript-package-in-monorepo": ["4.2.1", "4.2.2", "4.2.3", "4.2.4", "4.2.5", "4.2.6", "4.2.7", "4.2.8", "4.2.9", "4.2.10"],
  "qlik-chart-modules": ["1.1.1"],
  "qlik-modifiers": ["0.10.1"],
  "qlik-object-conversion": ["0.17.2"],
  "rstreams-shard-util": ["1.0.1"],
  "rwc-client": ["0.29.10", "0.29.11", "0.29.12", "0.29.13", "0.29.14", "0.29.15", "0.29.16", "0.29.17"],
  "server-hemera-mongo": ["0.0.12"],
  "sn-listbox": ["0.3.3"],
  "tslint-folder-schema": ["1.0.6", "1.0.7", "1.0.8", "1.0.9", "1.0.10", "1.0.11", "1.0.12", "1.0.13", "1.0.14", "1.0.15", "1.0.16", "1.0.17", "1.0.18", "1.0.19"],
  "verdaccio-okta-oauth": ["38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7", "38.1.8", "38.1.9", "38.1.10", "38.1.11", "38.1.12", "38.1.13", "38.1.14"],
  "verdaccio-tarball-local-storage": ["38.1.1", "38.1.2", "38.1.3", "38.1.4", "38.1.5", "38.1.6", "38.1.7", "38.1.8", "38.1.9", "38.1.10", "38.1.11", "38.1.12", "38.1.13", "38.1.14"],
  "workbench-browser-server": ["0.0.2"],
 }
};

ADVISORY.source = 'bundled snapshot of the ChainDrop (Shai-Hulud family, Aug 2026) IoC list — the campaign is ongoing and counts are still growing across trackers; supply a newer list with --database';

const INDEX = new Map();
for (const [name, versions] of Object.entries(ADVISORY.packages)) {
  INDEX.set(name, new Set(versions));
}

/** Replace the embedded advisory with an external JSON file ({packages:{name:[versions]}} or flat {name:[versions]}). */
function loadDatabase(file) {
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  const packages = raw.packages && typeof raw.packages === 'object' ? raw.packages : raw;
  INDEX.clear();
  let versionCount = 0;
  for (const [name, versions] of Object.entries(packages)) {
    if (!Array.isArray(versions)) continue;
    INDEX.set(name, new Set(versions.map(String)));
    versionCount += versions.length;
  }
  ADVISORY.id = raw.id || `custom (${path.basename(file)})`;
  ADVISORY.versionCount = versionCount;
  ADVISORY.packages = packages;
  ADVISORY.source = `external database: ${path.resolve(file)}`;
}

/** @returns {'critical'|'info'|null} */
function check(name, version) {
  const set = INDEX.get(name);
  if (!set) return null;
  return version && set.has(String(version).replace(/^v/, '')) ? 'critical' : 'info';
}

// ---------------------------------------------------------------------------
// Minimal semver: can a declared range still resolve to a compromised version?
// Unsupported/exotic ranges fail open so we warn rather than miss.
// ---------------------------------------------------------------------------
const SEMVER = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-.]+))?/;

function parseVer(v) {
  const m = SEMVER.exec(String(v).trim());
  return m ? { major: +m[1], minor: +m[2], patch: +m[3], pre: m[4] || '' } : null;
}

function cmp(a, b) {
  const x = typeof a === 'string' ? parseVer(a) : a;
  const y = typeof b === 'string' ? parseVer(b) : b;
  if (!x || !y) return 0;
  if (x.major !== y.major) return x.major < y.major ? -1 : 1;
  if (x.minor !== y.minor) return x.minor < y.minor ? -1 : 1;
  if (x.patch !== y.patch) return x.patch < y.patch ? -1 : 1;
  if (!x.pre && y.pre) return 1;
  if (x.pre && !y.pre) return -1;
  return x.pre === y.pre ? 0 : x.pre < y.pre ? -1 : 1;
}

function satisfiesOne(version, part) {
  const r = part.trim();
  if (!r || r === '*' || r === 'x' || r === 'latest') return true;

  const caret = /^\^\s*(.+)$/.exec(r);
  if (caret) {
    const p = parseVer(caret[1]);
    if (!p) return true;
    if (cmp(version, p) < 0) return false;
    const upper = p.major > 0 ? `${p.major + 1}.0.0`
      : p.minor > 0 ? `0.${p.minor + 1}.0`
        : `0.0.${p.patch + 1}`;
    return cmp(version, upper) < 0;
  }

  const tilde = /^~>?\s*(.+)$/.exec(r);
  if (tilde) {
    const p = parseVer(tilde[1]);
    if (!p) return true;
    return cmp(version, p) >= 0 && cmp(version, `${p.major}.${p.minor + 1}.0`) < 0;
  }

  const op = /^(>=|<=|>|<|=)\s*(.+)$/.exec(r);
  if (op) {
    const p = parseVer(op[2]);
    if (!p) return true;
    const c = cmp(version, p);
    return op[1] === '>' ? c > 0 : op[1] === '>=' ? c >= 0
      : op[1] === '<' ? c < 0 : op[1] === '<=' ? c <= 0 : c === 0;
  }

  // Partial versions: "1", "1.2", "1.2.x"
  const bits = r.replace(/^[v=]/, '').split('.');
  const nums = [];
  for (const b of bits) {
    if (b === 'x' || b === 'X' || b === '*' || b === '') break;
    if (!/^\d+$/.test(b)) return true;
    nums.push(+b);
  }
  if (!nums.length) return true;
  const lower = `${nums[0]}.${nums[1] || 0}.${nums[2] || 0}`;
  if (nums.length === 3) return cmp(version, lower) === 0;
  const upper = nums.length === 1 ? `${nums[0] + 1}.0.0` : `${nums[0]}.${nums[1] + 1}.0`;
  return cmp(version, lower) >= 0 && cmp(version, upper) < 0;
}

function satisfies(version, range) {
  if (!parseVer(version) || range == null) return false;
  let r = String(range).trim();
  if (!r) return true;
  const alias = /^npm:(?:.*@)?(.+)$/.exec(r);
  if (alias) r = alias[1];
  // Non-registry sources can't pull a published bad version.
  if (/^(file|link|workspace|git|git\+|github:|https?:|portal):/.test(r)) return false;

  for (const clause of r.split('||')) {
    const c = clause.trim();
    if (!c) continue;
    const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(c);
    if (hyphen) {
      if (cmp(version, hyphen[1]) >= 0 && cmp(version, hyphen[2]) <= 0) return true;
      continue;
    }
    if (c.split(/\s+/).every((p) => satisfiesOne(version, p))) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Dependency graph
// ---------------------------------------------------------------------------
function makeGraph() {
  const nodes = new Map();
  const parents = new Map();
  const children = new Map();
  const roots = new Set();

  const addNode = (n) => { if (!nodes.has(n.id)) nodes.set(n.id, n); };
  const addEdge = (from, to) => {
    if (from == null || to == null || from === to) return;
    if (!parents.has(to)) parents.set(to, new Set());
    parents.get(to).add(from);
    if (!children.has(from)) children.set(from, new Set());
    children.get(from).add(to);
  };

  const label = (id) => {
    const n = nodes.get(id);
    if (!n) return id;
    if (n.workspace) return n.name || '(root)';
    return n.version ? `${n.name}@${n.version}` : n.name;
  };

  // One multi-source BFS from all roots gives the shortest introduction path to
  // every node at once — O(V+E) total instead of a fresh BFS per finding.
  let bfsPrev = null;
  const ensureBfs = () => {
    if (bfsPrev) return;
    bfsPrev = new Map();
    const queue = [];
    for (const r of roots) { bfsPrev.set(r, null); queue.push(r); }
    let i = 0;
    while (i < queue.length) {
      const n = queue[i++];
      for (const c of children.get(n) || []) {
        if (!bfsPrev.has(c)) { bfsPrev.set(c, n); queue.push(c); }
      }
    }
  };

  const pathTo = (id) => {
    ensureBfs();
    if (!bfsPrev.has(id)) return [id];
    const chain = [];
    for (let n = id; n != null; n = bfsPrev.get(n)) chain.push(n);
    return chain.reverse();
  };

  // A child of a root is only "direct" when that root is a real workspace
  // (npm/pnpm/Berry). Yarn v1 has no workspace entries, so its roots are the
  // top-level packages themselves — those are the direct deps, not their kids.
  const isDirect = (id) => {
    if (roots.has(id)) return true;
    for (const p of parents.get(id) || []) {
      if (roots.has(p) && (nodes.get(p) || {}).workspace) return true;
    }
    return false;
  };

  return { nodes, parents, children, roots, addNode, addEdge, label, pathTo, isDirect };
}

// ---------------------------------------------------------------------------
// Lockfile parsers
// ---------------------------------------------------------------------------
function parseNpmLock(text) {
  const g = makeGraph();
  const lock = JSON.parse(text);

  if (lock.packages) {
    const pkgs = lock.packages;
    const resolve = (fromKey, dep) => {
      let base = fromKey;
      for (;;) {
        const cand = base ? `${base}/node_modules/${dep}` : `node_modules/${dep}`;
        if (Object.prototype.hasOwnProperty.call(pkgs, cand)) return cand;
        if (!base) return null;
        const i = base.lastIndexOf('/node_modules/');
        base = i === -1 ? '' : base.slice(0, i);
      }
    };

    for (const [key, e] of Object.entries(pkgs)) {
      if (e.link) continue;
      const isRoot = key === '' || !key.includes('node_modules/');
      const name = e.name || (isRoot ? key || '(root)' : key.slice(key.lastIndexOf('node_modules/') + 13));
      g.addNode({ id: key, name, version: e.version || null, workspace: isRoot, location: key || '.' });
      if (isRoot) g.roots.add(key);
    }
    for (const [key, e] of Object.entries(pkgs)) {
      const from = e.link ? e.resolved || key : key;
      const deps = { ...e.dependencies, ...e.devDependencies, ...e.optionalDependencies, ...e.peerDependencies };
      for (const dep of Object.keys(deps)) {
        const t = resolve(key, dep);
        if (!t) continue;
        g.addEdge(from, pkgs[t].link ? pkgs[t].resolved || t : t);
      }
    }
    return g;
  }

  if (lock.dependencies) {
    // v1: transitive packages are hoisted to the top level, so nesting says
    // nothing about who required them — `requires` does.
    const ROOT = '';
    g.addNode({ id: ROOT, name: lock.name || '(root)', workspace: true, location: '.' });
    g.roots.add(ROOT);
    const entries = new Map();
    const top = [];

    (function walk(deps, parentId, prefix) {
      for (const [name, e] of Object.entries(deps || {})) {
        const id = prefix ? `${prefix}/node_modules/${name}` : `node_modules/${name}`;
        g.addNode({ id, name, version: e.version || null, location: id });
        entries.set(id, e);
        if (parentId === ROOT) top.push(id); else g.addEdge(parentId, id);
        walk(e.dependencies, id, id);
      }
    })(lock.dependencies, ROOT, '');

    for (const [id, e] of entries) {
      for (const dep of Object.keys(e.requires && typeof e.requires === 'object' ? e.requires : {})) {
        let base = id;
        for (;;) {
          const cand = base ? `${base}/node_modules/${dep}` : `node_modules/${dep}`;
          if (g.nodes.has(cand)) { g.addEdge(id, cand); break; }
          if (!base) break;
          const i = base.lastIndexOf('/node_modules/');
          base = i === -1 ? '' : base.slice(0, i);
        }
      }
    }
    for (const id of top) if (!(g.parents.get(id) || {}).size) g.addEdge(ROOT, id);
  }
  return g;
}

function parseYarnLock(text) {
  const g = makeGraph();
  const unq = (v) => {
    const t = v.trim();
    if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) return t.slice(1, -1);
    return t;
  };

  // Headers come in two shapes: v1 quotes each descriptor separately
  // ("a@^1", "b@^2":) while Berry quotes the WHOLE list as one string
  // ("a@npm:^1, a@npm:^2":). Split at top level first, then split any token
  // that still carries commas — descriptors themselves can never contain one.
  const splitHeader = (header) => {
    const parts = [];
    let buf = '';
    let q = false;
    for (const ch of header) {
      if (ch === '"') { q = !q; continue; }
      if (ch === ',' && !q) { parts.push(buf); buf = ''; continue; }
      buf += ch;
    }
    parts.push(buf);
    return parts.flatMap((p) => p.split(',')).map((x) => x.trim()).filter(Boolean);
  };

  // First '@' past a possible leading scope '@' splits name from range. Using
  // the FIRST rather than the last keeps patch:/portal: descriptors sane
  // ("typescript@patch:typescript@npm%3A5.0.4#..." → name "typescript").
  const descName = (d) => {
    const at = d.indexOf('@', d.startsWith('@') ? 1 : 0);
    return at <= 0 ? { name: d, range: '*' } : { name: d.slice(0, at), range: d.slice(at + 1) };
  };

  const entries = [];
  let cur = null;
  let inDeps = false;
  let depIndent = 0;

  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim() || raw.trimStart().startsWith('#')) continue;
    const indent = raw.length - raw.trimStart().length;
    const line = raw.trim();

    if (indent === 0) {
      inDeps = false;
      if (!line.endsWith(':')) { cur = null; continue; }
      const header = line.slice(0, -1);
      if (header === '__metadata' || header === '"__metadata"') { cur = null; continue; }
      cur = { descriptors: splitHeader(header), version: null, resolution: null, deps: [] };
      entries.push(cur);
      continue;
    }
    if (!cur) continue;

    if (/^(dependencies|optionalDependencies):\s*$/.test(line)) { inDeps = true; depIndent = indent; continue; }
    if (inDeps && indent <= depIndent) inDeps = false;
    if (inDeps) {
      const m = /^("[^"]+"|[^\s:]+):?\s+(.+)$/.exec(line);
      if (m) cur.deps.push({ name: unq(m[1]), range: unq(m[2]) });
      continue;
    }
    let m;
    if ((m = /^version:?\s+(.+)$/.exec(line))) cur.version = unq(m[1]);
    else if ((m = /^resolution:\s+(.+)$/.exec(line))) cur.resolution = unq(m[1]);
  }

  const byDescriptor = new Map();
  const byName = new Map();
  for (const e of entries) {
    if (!e.version || !e.descriptors.length) continue;
    // resolution is canonical when present (Berry); descriptor is the v1 path.
    const { name } = descName(e.resolution || e.descriptors[0]);
    const isWorkspace = e.descriptors.some((d) => d.includes('@workspace:'))
      || (e.resolution && e.resolution.includes('@workspace:'));
    e.name = name;
    e.id = `${name}@${e.version}`;
    g.addNode({ id: e.id, name, version: e.version, workspace: isWorkspace, location: e.resolution || e.id });
    if (isWorkspace) g.roots.add(e.id);
    for (const d of e.descriptors) byDescriptor.set(d, e.id);
    if (!byName.has(name)) byName.set(name, []);
    byName.get(name).push(e);
  }

  for (const e of entries) {
    if (!e.id) continue;
    for (const d of e.deps) {
      const bare = d.range.replace(/^npm:/, '');
      let target = byDescriptor.get(`${d.name}@${d.range}`)
        || byDescriptor.get(`${d.name}@npm:${bare}`)
        || byDescriptor.get(`${d.name}@${bare}`);
      if (!target) {
        // patch:/alias descriptors rarely match verbatim; fall back to semver.
        const cands = byName.get(d.name) || [];
        if (cands.length === 1) target = cands[0].id;
        else {
          const hit = cands.find((c) => satisfies(c.version, bare));
          if (hit) target = hit.id;
        }
      }
      if (target) g.addEdge(e.id, target);
    }
  }

  // Berry marks workspaces explicitly; classic v1 has no such concept, so fall
  // back to treating parentless entries as the installation surface.
  if (!g.roots.size) {
    for (const id of g.nodes.keys()) if (!(g.parents.get(id) || { size: 0 }).size) g.roots.add(id);
  }
  return g;
}

function parsePnpmLock(text) {
  const g = makeGraph();
  const clean = (v) => v.replace(/^["']|["']$/g, '');

  // Peer-dependency suffixes come in two dialects: parenthesised in v6/v9
  // ("1.0.0(react@17.0.2)") and underscore-joined in v5 ("1.0.0_react@17.0.2").
  // Both must be stripped before a version is usable, and only when the string
  // actually starts like a version — package names may legally contain "_".
  const strip = (v) => {
    let x = v;
    const paren = x.indexOf('(');
    if (paren !== -1) x = x.slice(0, paren);
    if (/^\d/.test(x)) {
      const us = x.indexOf('_');
      if (us !== -1) x = x.slice(0, us);
    }
    return x;
  };

  /** Accepts "/name/1.0.0_peer", "/name@1.0.0(peer)", "name@1.0.0". */
  const splitKey = (raw) => {
    let k = clean(raw.trim());
    const paren = k.indexOf('(');
    if (paren !== -1) k = k.slice(0, paren);
    if (k.startsWith('/')) k = k.slice(1);
    // at-form: first "@" (past a leading scope) whose remainder starts with a
    // digit — but a name containing "/1.4.0"-style segments means this is a
    // v5 slash-form key whose peer suffix ("_react@17.0.2") is masquerading
    // as the version separator, so reject and fall through to slash parsing.
    let at = k.indexOf('@', k.startsWith('@') ? 1 : 0);
    while (at !== -1 && !/^\d/.test(k.slice(at + 1))) at = k.indexOf('@', at + 1);
    if (at > 0 && !/\/\d+\./.test(k.slice(0, at))) {
      return { name: k.slice(0, at), version: strip(k.slice(at + 1)) };
    }
    const sl = k.lastIndexOf('/');
    if (sl > 0 && /^\d+\./.test(k.slice(sl + 1))) return { name: k.slice(0, sl), version: strip(k.slice(sl + 1)) };
    return null;
  };

  const declare = (name, version) => {
    const id = `${name}@${version}`;
    g.addNode({ id, name, version, location: id });
    return id;
  };

  let section = null;
  let importer = null;
  let cur = null;
  let inDeps = false;
  const pending = [];

  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim() || raw.trimStart().startsWith('#')) continue;
    const indent = raw.length - raw.trimStart().length;
    const line = raw.trim();

    if (indent === 0) { section = line.replace(/:.*$/, ''); cur = importer = null; inDeps = false; continue; }

    if (section === 'importers') {
      if (indent === 2) {
        importer = clean(line.replace(/:$/, ''));
        const id = `workspace:${importer}`;
        g.addNode({ id, name: importer, workspace: true, location: importer });
        g.roots.add(id);
        inDeps = false;
      } else if (indent === 4) {
        inDeps = /^(dependencies|devDependencies|optionalDependencies):/.test(line);
        if (!inDeps) {
          const m = /^(.+?):\s*(.*)$/.exec(line);
          if (m) pending.push({ from: `workspace:${importer}`, name: clean(m[1]), version: m[2] ? strip(clean(m[2])) : null });
        }
      } else if (inDeps && indent === 6) {
        const m = /^(.+?):\s*(.*)$/.exec(line);
        if (m) pending.push({ from: `workspace:${importer}`, name: clean(m[1]), version: m[2] ? strip(clean(m[2])) : null });
      } else if (indent === 8) {
        const m = /^version:\s*(.+)$/.exec(line);
        const last = pending[pending.length - 1];
        if (m && last && !last.version) last.version = strip(clean(m[1]));
      }
      continue;
    }

    if (section === 'packages' || section === 'snapshots') {
      if (indent === 2 && line.endsWith(':')) {
        const p = splitKey(line.slice(0, -1));
        cur = p ? declare(p.name, p.version) : null;
        inDeps = false;
      } else if (indent === 4) {
        inDeps = /^(dependencies|optionalDependencies):/.test(line);
      } else if (inDeps && indent > 4 && cur) {
        const m = /^(.+?):\s*(.+)$/.exec(line);
        if (m) {
          const version = strip(clean(m[2]));
          if (/^\d/.test(version)) g.addEdge(cur, declare(clean(m[1]), version));
        }
      }
    }
  }

  for (const d of pending) {
    if (d.version && /^\d/.test(d.version)) g.addEdge(d.from, declare(d.name, d.version));
  }
  if (!g.roots.size) {
    for (const id of g.nodes.keys()) if (!(g.parents.get(id) || {}).size) g.roots.add(id);
  }
  return g;
}

const PARSERS = {
  'package-lock.json': parseNpmLock,
  'npm-shrinkwrap.json': parseNpmLock,
  'yarn.lock': parseYarnLock,
  'pnpm-lock.yaml': parsePnpmLock,
};

// ---------------------------------------------------------------------------
// Filesystem discovery
// ---------------------------------------------------------------------------
const SKIP_DIRS = new Set(['.git', '.hg', '.cache', '.next', '.nuxt', '.turbo', '.yarn',
  'dist', 'build', 'out', 'coverage', 'tmp', 'venv', '.venv', '__pycache__']);

// Directories that are never a project but are enormous and full of
// package.json files — OS profile stores, browser profiles, package-manager
// caches, temp dirs. Walking these is what makes a scan of a home directory
// appear to hang: a single Yarn cache can hold tens of thousands of package
// directories, none of which is an installed dependency of anything.
// Matched case-insensitively because Windows and macOS paths are not
// case-sensitive.
const NOISE_DIRS = new Set([
  'appdata', 'application data', 'library', 'windows', 'program files',
  'program files (x86)', 'programdata', '$recycle.bin', 'system volume information',
  'temp', 'temporary internet files', '.trash', 'trash',
  'cache', 'caches', 'cache2', '.cache', 'cachestorage',
  '.npm', '.yarn', '.pnpm-store', '.bun', '.deno', '.nvm', '.gradle', '.m2',
  'msys64', 'anaconda3', 'miniconda3',
]);

const isNoiseDir = (name) => NOISE_DIRS.has(name.toLowerCase());

const UNSUPPORTED_LOCKFILES = new Set(['bun.lock', 'bun.lockb', 'deno.lock']);

async function discover(root, maxDepth = 12, onProgress) {
  const lockfiles = [];
  const manifests = [];
  const nodeModules = [];
  const unsupported = [];
  const visited = new Set();
  let dirsSeen = 0;
  let level = [{ dir: root, depth: 0 }];

  while (level.length) {
    const next = [];
    const batch = await Promise.all(level.map(async ({ dir, depth }) => {
      // Dedupe on the real path, not the literal one: a symlink that points
      // back up the tree produces endlessly-growing distinct paths, so
      // resolve()-based dedup never catches the cycle.
      let real;
      try { real = await fsp.realpath(dir); } catch { return null; }
      if (visited.has(real)) return null;
      visited.add(real);
      try { return { dir, depth, entries: await fsp.readdir(dir, { withFileTypes: true }) }; }
      catch { return null; }
    }));

    for (const b of batch) {
      if (!b) continue;
      if (onProgress && ++dirsSeen % 200 === 0) onProgress({ phase: 'walk', dirsSeen, dir: b.dir });
      for (const e of b.entries) {
        const full = path.join(b.dir, e.name);
        if (e.isDirectory()) {
          if (e.name === 'node_modules') { nodeModules.push(full); continue; }
          if (SKIP_DIRS.has(e.name) || isNoiseDir(e.name) || e.name.startsWith('.')) continue;
          if (b.depth < maxDepth) next.push({ dir: full, depth: b.depth + 1 });
        } else if (e.isFile()) {
          if (PARSERS[e.name]) lockfiles.push(full);
          else if (UNSUPPORTED_LOCKFILES.has(e.name)) unsupported.push(full);
          else if (e.name === 'package.json') manifests.push(full);
        }
      }
    }
    level = next;
  }
  return { lockfiles, manifests, nodeModules, unsupported };
}

/**
 * Walk node_modules without reading it. Directory names are package names, so
 * membership is tested before touching disk — a 25k-module tree costs 25k
 * readdir entries and a handful of reads, not 25k reads.
 */
async function scanInstalled(nmRoot, opts = {}) {
  const ig = opts.ignoreSet && opts.ignoreSet.size ? opts.ignoreSet : null;
  const found = [];
  const seen = new Set();
  const maxNest = opts.maxNest == null ? 40 : opts.maxNest;
  const queue = [{ dir: nmRoot, depth: 0 }];

  const readManifest = async (dir, fallback) => {
    try {
      const p = JSON.parse(await fsp.readFile(path.join(dir, 'package.json'), 'utf8'));
      return { name: p.name || fallback, version: p.version || null, scripts: p.scripts || {} };
    } catch { return { name: fallback, version: null, scripts: {} }; }
  };

  const record = (name, version, dir, scripts) => {
    if (ig && ig.has(name)) return;
    const severity = check(name, version);
    if (!severity) return;
    found.push({
      name, version, dir, severity,
      hooks: ['preinstall', 'install', 'postinstall', 'prepare'].filter((h) => scripts && scripts[h]),
    });
  };

  const visit = async ({ dir: rawDir, depth }) => {
    // Nested node_modules legitimately go a few levels deep; a hundred means
    // a symlink cycle. Linux stops these with ELOOP at ~40 links, but Windows
    // with long paths enabled will happily keep resolving, so cap explicitly.
    if (depth > maxNest) return;
    const nmDir = path.resolve(rawDir);
    // Resolve symlinks before the dedup check — pnpm and npm both symlink
    // heavily, and a cycle produces distinct literal paths every iteration.
    let real;
    try { real = await fsp.realpath(nmDir); } catch { return; }
    if (seen.has(real)) return;
    seen.add(real);

    let entries;
    try { entries = await fsp.readdir(nmDir, { withFileTypes: true }); } catch { return; }

    for (const e of entries) {
      if (!e.isDirectory() && !e.isSymbolicLink()) continue;
      const name = e.name;
      if (name === '.bin') continue;

      if (name === '.pnpm') {
        // Store dir names encode name@version directly — no reads needed.
        let store;
        try { store = await fsp.readdir(path.join(nmDir, name), { withFileTypes: true }); } catch { continue; }
        for (const s of store) {
          if (!s.isDirectory()) continue;
          const base = s.name.split('_')[0];
          const at = base.lastIndexOf('@');
          if (at <= 0) continue;
          const pkgName = base.slice(0, at).replace('+', '/');
          if (!INDEX.has(pkgName)) continue;
          const dir = path.join(nmDir, name, s.name, 'node_modules', ...pkgName.split('/'));
          const m = await readManifest(dir, pkgName);
          record(pkgName, m.version || base.slice(at + 1), dir, m.scripts);
        }
        continue;
      }
      if (name.startsWith('.')) continue;

      if (name.startsWith('@')) {
        const scopeDir = path.join(nmDir, name);
        let scoped;
        try { scoped = await fsp.readdir(scopeDir, { withFileTypes: true }); } catch { continue; }
        for (const s of scoped) {
          const full = `${name}/${s.name}`;
          const dir = path.join(scopeDir, s.name);
          if (INDEX.has(full)) {
            const m = await readManifest(dir, full);
            record(m.name, m.version, dir, m.scripts);
          }
          queue.push({ dir: path.join(dir, 'node_modules'), depth: depth + 1 });
        }
        continue;
      }

      const dir = path.join(nmDir, name);
      if (INDEX.has(name)) {
        const m = await readManifest(dir, name);
        record(m.name, m.version, dir, m.scripts);
      }
      queue.push({ dir: path.join(dir, 'node_modules'), depth: depth + 1 });
    }
  };

  // Drain in parallel waves; directory reads are latency-bound, not CPU-bound.
  const width = 32;
  while (queue.length) {
    await Promise.all(queue.splice(0, width).map(visit));
  }
  return found;
}

// ---------------------------------------------------------------------------
// Bounded-concurrency pool — shared by lockfile parsing, node_modules
// scanning and the system-mode repo sweep so I/O-bound work overlaps instead
// of running one file at a time.
// ---------------------------------------------------------------------------
async function mapPool(items, limit, worker) {
  const n = Math.max(1, Math.min(limit, items.length) || 1);
  let cursor = 0;
  const results = new Array(items.length);
  async function run() {
    for (;;) {
      const i = cursor++;
      if (i >= items.length) return;
      results[i] = await worker(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: n }, run));
  return results;
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------
const RANK = { critical: 3, warning: 2, info: 1 };
const MANIFEST_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies',
  'peerDependencies', 'resolutions', 'overrides'];

async function scan(root, opts = {}) {
  const started = Date.now();
  const absRoot = path.resolve(root);
  const findings = new Map();
  const errors = [];
  const ig = opts.ignoreSet && opts.ignoreSet.size ? opts.ignoreSet : null;
  const onProgress = opts.onProgress || (() => {});
  let inspected = 0;

  const rel = (f) => path.relative(absRoot, f) || path.basename(f);

  const add = (name, version, severity, evidence, extra = {}) => {
    const key = `${name}@${version || '*'}`;
    let f = findings.get(key);
    if (!f) {
      f = {
        package: name,
        version: version || null,
        severity,
        direct: false,
        compromisedVersions: [...(INDEX.get(name) || [])],
        introducedBy: [],
        hooks: [],
        evidence: [],
      };
      findings.set(key, f);
    }
    if (RANK[severity] > RANK[f.severity]) f.severity = severity;
    if (extra.direct) f.direct = true;
    if (extra.chain && !f.introducedBy.includes(extra.chain)) f.introducedBy.push(extra.chain);
    if (extra.hooks) f.hooks = [...new Set([...f.hooks, ...extra.hooks])];
    f.evidence.push({ ...evidence, file: rel(evidence.file) });
    return f;
  };

  onProgress({ phase: 'discover', root: absRoot });
  if (!fs.existsSync(absRoot)) {
    errors.push({ file: '', stage: 'root', message: `path does not exist: ${absRoot}` });
    onProgress({ phase: 'scan-done', findings: 0 });
    return {
      mode: 'project',
      root: absRoot,
      advisory: { id: ADVISORY.id, packages: INDEX.size, versions: ADVISORY.versionCount, source: ADVISORY.source },
      scanned: { lockfiles: 0, manifests: 0, nodeModules: 0, packagesInspected: 0 },
      counts: { critical: 0, warning: 0, info: 0 },
      findings: [],
      errors,
      durationMs: Date.now() - started,
    };
  }
  const { lockfiles, manifests, nodeModules, unsupported } = await discover(absRoot, opts.maxDepth, onProgress);
  onProgress({ phase: 'discovered', lockfiles: lockfiles.length, manifests: manifests.length, nodeModules: nodeModules.length });

  for (const file of unsupported) {
    errors.push({ file: rel(file), stage: 'discover', message: `unsupported lockfile format — ${path.basename(file)} was not scanned` });
  }

  if (opts.manifests !== false) {
    await Promise.all(manifests.map(async (file) => {
      let pkg;
      try { pkg = JSON.parse(await fsp.readFile(file, 'utf8')); }
      catch (err) {
        errors.push({ file: rel(file), stage: 'manifest', message: `unreadable or invalid JSON (${err.message})` });
        return;
      }
      for (const field of MANIFEST_FIELDS) {
        const block = pkg[field];
        if (!block || typeof block !== 'object') continue;
        for (const [name, range] of Object.entries(block)) {
          if (!INDEX.has(name) || typeof range !== 'string') continue;
          if (ig && ig.has(name)) continue;
          const hits = [...INDEX.get(name)].filter((v) => satisfies(v, range));
          add(name, null, hits.length ? 'warning' : 'info',
            { type: 'manifest', file, location: `${field}.${name}`, range, matches: hits },
            { direct: true });
        }
      }
    }));
  }

  if (opts.lockfiles !== false) {
    // Reading and parsing each lockfile is independent I/O + CPU work, so it
    // runs through the same bounded pool as the repo sweep instead of one
    // file at a time — the only shared state (`findings`, via add()) is
    // mutated synchronously between awaits, so concurrent completions never race.
    let lockDone = 0;
    await mapPool(lockfiles, opts.concurrency || 8, async (file) => {
      let text;
      try { text = await fsp.readFile(file, 'utf8'); }
      catch (err) {
        errors.push({ file: rel(file), stage: 'read', message: err.message });
        onProgress({ phase: 'lockfile', current: ++lockDone, total: lockfiles.length, file: rel(file) });
        return;
      }
      let g;
      try { g = PARSERS[path.basename(file)](text); }
      catch (err) {
        errors.push({ file: rel(file), stage: 'parse', message: `parser failed: ${err.message}` });
        onProgress({ phase: 'lockfile', current: ++lockDone, total: lockfiles.length, file: rel(file) });
        return;
      }
      if (g.nodes.size === 0 && text.replace(/(^|\n)\s*#[^\n]*/g, '').trim().length > 0) {
        errors.push({ file: rel(file), stage: 'parse', message: 'no packages parsed — unrecognized format variant; results for this file are incomplete' });
        onProgress({ phase: 'lockfile', current: ++lockDone, total: lockfiles.length, file: rel(file) });
        return;
      }
      inspected += g.nodes.size;
      for (const node of g.nodes.values()) {
        if (node.workspace) continue;
        if (ig && ig.has(node.name)) continue;
        const severity = check(node.name, node.version);
        if (!severity) continue;
        add(node.name, node.version, severity,
          { type: 'lockfile', file, location: node.location },
          {
            direct: g.isDirect(node.id),
            chain: g.pathTo(node.id).map(g.label).join(' › '),
          });
      }
      onProgress({ phase: 'lockfile', current: ++lockDone, total: lockfiles.length, file: rel(file) });
    });
  }

  if (opts.nodeModules !== false) {
    let nmDone = 0;
    await mapPool(nodeModules, opts.concurrency || 8, async (nm) => {
      for (const hit of await scanInstalled(nm, { ignoreSet: ig })) {
        add(hit.name, hit.version, hit.severity,
          { type: 'installed', file: hit.dir, location: path.relative(absRoot, hit.dir) },
          { hooks: hit.hooks });
      }
      onProgress({ phase: 'nodeModules', current: ++nmDone, total: nodeModules.length, dir: path.relative(absRoot, nm) });
    });
  }

  // A manifest range finding and a lockfile finding for the same package are
  // one problem seen twice — but only when the declared range can actually
  // resolve to that concrete version. "ecto@^4.0.0" in package.json must not
  // mark a transitive ecto@5.0.1 as direct.
  const concrete = new Map();
  for (const f of findings.values()) {
    if (!f.version) continue;
    if (!concrete.has(f.package)) concrete.set(f.package, []);
    concrete.get(f.package).push(f);
  }
  for (const [key, f] of [...findings]) {
    if (f.version || !concrete.has(f.package)) continue;
    let folded = false;
    for (const t of concrete.get(f.package)) {
      const applies = f.evidence.some((e) => e.range != null && satisfies(t.version, e.range));
      if (!applies) continue;
      t.evidence.push(...f.evidence);
      if (f.direct) t.direct = true;
      if (RANK[f.severity] > RANK[t.severity]) t.severity = f.severity;
      folded = true;
    }
    if (folded) findings.delete(key);
  }

  const list = [...findings.values()].sort((a, b) =>
    RANK[b.severity] - RANK[a.severity] || a.package.localeCompare(b.package));

  const counts = { critical: 0, warning: 0, info: 0 };
  for (const f of list) counts[f.severity]++;

  onProgress({ phase: 'scan-done', findings: findings.size });

  return {
    mode: 'project',
    root: absRoot,
    advisory: { id: ADVISORY.id, packages: INDEX.size, versions: ADVISORY.versionCount, source: ADVISORY.source },
    scanned: {
      lockfiles: lockfiles.length,
      manifests: manifests.length,
      nodeModules: nodeModules.length,
      packagesInspected: inspected,
    },
    counts,
    findings: list,
    errors,
    durationMs: Date.now() - started,
  };
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------
const color = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code) => (t) => (color ? `\u001b[${code}m${t}\u001b[0m` : t);
const red = paint('31;1');
const yellow = paint('33;1');
const blue = paint('36');
const dim = paint('2');
const bold = paint('1');
const green = paint('32;1');

const LABEL = { critical: red('CRITICAL'), warning: yellow(' WARNING'), info: blue('   INFO ') };
const WHY = {
  critical: 'compromised version is installed or pinned in a lockfile',
  warning: 'declared range can still resolve to a compromised version',
  info: 'package is in the advisory but this resolved version is not listed',
};

function shorten(chain, tag = (t) => t) {
  const parts = chain.split(' › ');
  if (parts.length <= 5) return chain;
  return [...parts.slice(0, 2), tag(`… ${parts.length - 4} more …`), ...parts.slice(-2)].join(' › ');
}

function versionsFor(name) {
  const set = INDEX.get(name);
  return set ? [...set] : [];
}

/** Plain-text evidence lines, deduped, shared by the terminal, HTML and CSV reports. */
function evidenceLines(f) {
  const seen = new Set();
  const out = [];
  for (const e of f.evidence) {
    const detail = e.type === 'manifest'
      ? `${e.file} → ${e.location} = "${e.range}"${e.matches && e.matches.length ? ` (matches ${e.matches.join(', ')})` : ''}`
      : `${e.file}${e.type === 'lockfile' ? ` → ${e.location}` : ''}`;
    const line = `${e.type}: ${detail}`;
    if (seen.has(line)) continue;
    seen.add(line);
    out.push(line);
  }
  return out;
}

function report(r) {
  const out = [];
  out.push(bold(`ChainDrop scan — ${r.root}`));
  out.push(dim(`${r.advisory.packages} packages / ${r.advisory.versions} compromised versions (${r.advisory.source}) · `
    + `${r.scanned.lockfiles} lockfile(s), ${r.scanned.manifests} manifest(s), `
    + `${r.scanned.packagesInspected} locked packages inspected in ${r.durationMs}ms`));
  out.push('');

  const errBlock = () => {
    if (!r.errors || !r.errors.length) return;
    out.push('');
    out.push(yellow(`⚠ ${r.errors.length} scan warning(s) — results may be incomplete:`));
    for (const e of r.errors.slice(0, 10)) out.push(`  ${dim(`[${e.stage}]`)} ${e.file ? `${e.file}: ` : ''}${e.message}`);
    if (r.errors.length > 10) out.push(dim(`  … and ${r.errors.length - 10} more`));
  };

  if (!r.findings.length) {
    if (r.errors && r.errors.length) {
      out.push(yellow('No compromised packages found, but parts of this tree could not be fully scanned — this is NOT a verified-clean result.'));
      errBlock();
    } else {
      out.push(green('✔ No ChainDrop-compromised packages found.'));
      out.push(dim('A clean result covers what is resolvable here. Without a lockfile, ranges could still float onto a bad version.'));
    }
    return out.join('\n');
  }

  for (const f of r.findings) {
    out.push(`${LABEL[f.severity]}  ${bold(f.package)}${f.version ? `@${f.version}` : ''}`);
    out.push(`          ${dim(WHY[f.severity])}`);
    out.push(`          ${dim('reach:')} ${f.direct ? 'direct dependency' : 'transitive dependency'}`);
    for (const chain of f.introducedBy.slice(0, 3)) {
      if (chain.includes(' › ')) out.push(`          ${dim('via:')}   ${shorten(chain, dim)}`);
    }
    if (f.introducedBy.length > 3) out.push(`          ${dim(`… and ${f.introducedBy.length - 3} more path(s)`)}`);
    if (f.hooks.length) out.push(`          ${red('install hooks:')} ${f.hooks.join(', ')} ${dim('(payload runs on install)')}`);

    for (const line of evidenceLines(f)) out.push(`          ${dim(line)}`);

    const v = f.compromisedVersions;
    if (v.length) {
      out.push(`          ${dim('compromised versions:')} ${v.length > 8 ? `${v.slice(0, 8).join(', ')} … (+${v.length - 8})` : v.join(', ')}`);
    }
    out.push('');
  }

  out.push(bold('Summary'));
  out.push(`  ${red('critical')} ${r.counts.critical}   ${yellow('warning')} ${r.counts.warning}   ${blue('info')} ${r.counts.info}`);
  errBlock();
  return out.join('\n');
}

// ---------------------------------------------------------------------------
// System-wide mode: find every code repo on the machine, plus global installs
// ---------------------------------------------------------------------------

/**
 * Directories that are never worth descending into. Package manager caches are
 * deliberately NOT here — a compromised tarball sitting in the npx or yarn
 * cache will be reinstalled without ever touching the registry again.
 */
// Note: entries here are matched against a single directory NAME, so a path
// fragment like 'AppData\\Local\\Temp' could never match — that is handled by
// NOISE_DIRS ('appdata', 'temp') instead.
const SYSTEM_SKIP = new Set([
  'proc', 'sys', 'dev', 'run', 'boot', 'lost+found', 'System', 'Volumes',
  'private', 'Applications', '.Trash', 'Trash', '.git',
  'Photos Library.photoslibrary', 'node_modules',
]);

function homeDir() {
  return process.env.HOME || process.env.USERPROFILE || require('os').homedir();
}

/** Default search roots when the user doesn't name any. */
function defaultRoots() {
  const home = homeDir();
  const roots = [home];
  for (const extra of ['/srv', '/opt', '/var/www', '/workspace', '/workspaces', '/repos', '/code']) {
    try { if (fs.statSync(extra).isDirectory()) roots.push(extra); } catch { /* absent */ }
  }
  return roots;
}

/**
 * Where package managers put globally installed code. These run with your
 * shell's privileges and are exactly what a token-stealing worm wants.
 */
function globalRoots() {
  const home = homeDir();
  const candidates = [
    '/usr/lib/node_modules',
    '/usr/local/lib/node_modules',
    '/usr/local/share/npm/lib/node_modules',
    '/opt/homebrew/lib/node_modules',
    path.join(home, '.npm-global/lib/node_modules'),
    path.join(home, '.npm/_npx'),
    path.join(home, '.config/yarn/global/node_modules'),
    path.join(home, '.yarn/global/node_modules'),
    path.join(home, '.local/share/pnpm/global'),
    path.join(home, '.pnpm-store'),
    path.join(home, 'Library/pnpm/global'),
    path.join(home, 'AppData/Roaming/npm/node_modules'),
    path.join(home, '.bun/install/global/node_modules'),
  ];

  // Version managers keep one node_modules per installed runtime.
  for (const vm of ['.nvm/versions/node', '.volta/tools/image/node', '.fnm/node-versions', '.asdf/installs/nodejs']) {
    const base = path.join(home, vm);
    let versions;
    try { versions = fs.readdirSync(base); } catch { continue; }
    for (const v of versions) {
      candidates.push(path.join(base, v, 'lib/node_modules'));
      candidates.push(path.join(base, v, 'installs/lib/node_modules'));
    }
  }

  // Ask npm directly as a backstop for unusual prefixes.
  try {
    const out = require('child_process')
      .execFileSync('npm', ['root', '-g'], { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] })
      .trim();
    if (out) candidates.push(out);
  } catch { /* npm not on PATH */ }

  const seen = new Set();
  return candidates.filter((c) => {
    const r = path.resolve(c);
    if (seen.has(r)) return false;
    seen.add(r);
    try { return fs.statSync(r).isDirectory(); } catch { return false; }
  });
}

/**
 * Breadth-first sweep for repo roots. A directory is a repo if it holds a .git,
 * a lockfile, or a package.json; we record it and stop descending, because the
 * per-repo scan recurses through its own workspaces. That keeps monorepo
 * packages from being counted as separate repos and keeps the sweep shallow.
 */
async function findRepos(roots, opts = {}) {
  const maxDepth = opts.maxDepth == null ? 10 : opts.maxDepth;
  const limit = opts.maxRepos || 5000;
  const repos = [];
  const visited = new Set();
  let level = roots.map((dir) => ({ dir: path.resolve(dir), depth: 0 }));
  let dirsSeen = 0;

  while (level.length && repos.length < limit) {
    const next = [];
    const batch = await Promise.all(level.map(async ({ dir, depth }) => {
      let real;
      try { real = await fsp.realpath(dir); } catch { return null; }
      if (visited.has(real)) return null;   // symlink loops
      visited.add(real);
      try { return { dir, depth, entries: await fsp.readdir(dir, { withFileTypes: true }) }; }
      catch { return null; }                // unreadable: permissions, vanished
    }));

    for (const b of batch) {
      if (!b) continue;
      dirsSeen++;
      let isRepo = false;
      const subdirs = [];

      for (const e of b.entries) {
        if (e.isFile() && (PARSERS[e.name] || UNSUPPORTED_LOCKFILES.has(e.name) || e.name === 'package.json')) isRepo = true;
        else if (e.isDirectory()) {
          if (e.name === '.git') isRepo = true;
          else subdirs.push(e.name);
        }
      }

      if (isRepo) {
        repos.push(b.dir);
        if (repos.length >= limit) return { repos, dirsSeen, truncated: true };
        continue;
      }
      if (b.depth >= maxDepth) continue;

      for (const name of subdirs) {
        if (SYSTEM_SKIP.has(name) || isNoiseDir(name)) continue;
        // Hidden dirs are skipped except the package-manager caches we care about.
        if (name.startsWith('.') && !['.npm', '.cache', '.yarn', '.pnpm-store', '.local'].includes(name)) continue;
        next.push({ dir: path.join(b.dir, name), depth: b.depth + 1 });
      }
    }
    level = next;
  }
  return { repos, dirsSeen, truncated: false };
}

async function scanSystem(roots, opts = {}) {
  const started = Date.now();
  const onProgress = opts.onProgress || (() => {});

  onProgress({ phase: 'system-discover' });
  const { repos, dirsSeen, truncated } = await findRepos(roots, opts);
  onProgress({ phase: 'system-discovered', repos: repos.length });

  // Repos are independent I/O-bound units of work, scanned concurrently
  // through the shared pool. Order is preserved via index slots so output
  // stays deterministic regardless of which worker finishes first. A repo's
  // own scan() runs its lockfiles through the *same* pool internally, so
  // --concurrency caps total in-flight file operations, not just repo count.
  const scanned = new Array(repos.length).fill(null);
  let packagesInspected = 0;
  let completed = 0;
  const concurrency = Math.max(1, opts.concurrency || 6);

  const allErrors = [];
  await mapPool(repos, concurrency, async (repoRoot, i) => {
    let r;
    try { r = await scan(repoRoot, { ...opts, onProgress: undefined }); }
    catch (err) {
      allErrors.push({ repo: repoRoot, file: '', stage: 'scan', message: err.message });
      onProgress({ phase: 'system-repo', current: ++completed, total: repos.length, repo: repoRoot });
      return;
    }
    packagesInspected += r.scanned.packagesInspected;
    // Errors are collected even from repos with zero findings — a repo that
    // failed to parse must never look identical to a repo that came up clean.
    for (const e of r.errors) allErrors.push({ repo: repoRoot, ...e });
    if (r.findings.length) scanned[i] = { root: repoRoot, kind: 'repo', result: r };
    onProgress({ phase: 'system-repo', current: ++completed, total: repos.length, repo: repoRoot });
  });
  const scannedRepos = scanned.filter(Boolean);

  const globals = [];
  if (opts.globals !== false) {
    const gRoots = globalRoots();
    let gDone = 0;
    const results = await mapPool(gRoots, concurrency, async (g) => {
      let out;
      try { out = { root: g, hits: await scanInstalled(g, { ignoreSet: opts.ignoreSet }) }; } catch { out = null; }
      onProgress({ phase: 'system-globals', current: ++gDone, total: gRoots.length, root: g });
      return out;
    });
    for (const g of results) if (g && g.hits.length) globals.push(g);
  }

  // Roll up: which packages are affected, and how widely.
  const rollup = new Map();
  const bump = (name, version, severity, where) => {
    const key = `${name}@${version || '*'}`;
    if (!rollup.has(key)) rollup.set(key, { package: name, version: version || null, severity, locations: new Set() });
    const e = rollup.get(key);
    if (RANK[severity] > RANK[e.severity]) e.severity = severity;
    e.locations.add(where);
  };
  for (const s of scannedRepos) for (const f of s.result.findings) bump(f.package, f.version, f.severity, s.root);
  for (const g of globals) for (const h of g.hits) bump(h.name, h.version, h.severity, g.root);

  const counts = { critical: 0, warning: 0, info: 0 };
  for (const e of rollup.values()) counts[e.severity]++;

  return {
    mode: 'system',
    roots: roots.map((r) => path.resolve(r)),
    scanned: {
      directoriesSeen: dirsSeen,
      reposFound: repos.length,
      truncated: !!truncated,
      reposAffected: scannedRepos.length,
      globalRootsAffected: globals.length,
      packagesInspected,
    },
    counts,
    repos: scannedRepos,
    globals,
    errors: allErrors,
    affectedPackages: [...rollup.values()]
      .map((e) => ({ ...e, locations: [...e.locations] }))
      .sort((a, b) => RANK[b.severity] - RANK[a.severity] || b.locations.length - a.locations.length),
    durationMs: Date.now() - started,
  };
}

function reportSystem(r) {
  const out = [];
  const secs = (r.durationMs / 1000).toFixed(1);
  out.push(bold(`ChainDrop system scan — ${r.roots.join(', ')}`));
  out.push(dim(`${r.scanned.reposFound} repos found across ${r.scanned.directoriesSeen} directories · `
    + `${r.scanned.packagesInspected} locked packages inspected · ${secs}s`));
  if (r.scanned.truncated) {
    out.push(yellow(`⚠ Stopped at the --max-repos limit of ${r.scanned.reposFound}; the sweep is incomplete.`));
  }
  out.push('');

  const sysErrBlock = () => {
    if (!r.errors || !r.errors.length) return;
    out.push('');
    out.push(yellow(`⚠ ${r.errors.length} scan warning(s) across the sweep — results may be incomplete:`));
    for (const e of r.errors.slice(0, 8)) out.push(`  ${dim(`[${e.stage}]`)} ${e.repo}${e.file ? `/${e.file}` : ''}: ${e.message}`);
    if (r.errors.length > 8) out.push(dim(`  … and ${r.errors.length - 8} more`));
  };

  if (!r.repos.length && !r.globals.length) {
    if (r.errors && r.errors.length) {
      out.push(yellow(`No compromised packages found in ${r.scanned.reposFound} repositories, but some could not be fully scanned — this is NOT a verified-clean result.`));
      sysErrBlock();
    } else {
      out.push(green(`✔ No ChainDrop-compromised packages found in ${r.scanned.reposFound} repositories or any global install location.`));
      out.push(dim('Repos without a lockfile are only checked at the range level — an unpinned install could still pull a bad version.'));
    }
    return out.join('\n');
  }

  for (const s of r.repos) {
    const c = s.result.counts;
    out.push(bold(s.root) + dim(`  (${c.critical} critical, ${c.warning} warning, ${c.info} info)`));
    for (const f of s.result.findings) {
      const tag = f.severity === 'critical' ? red('critical') : f.severity === 'warning' ? yellow('warning ') : blue('info    ');
      out.push(`  ${tag}  ${f.package}${f.version ? `@${f.version}` : ''}`
        + dim(f.direct ? '  direct' : '  transitive')
        + (f.introducedBy[0] && f.introducedBy[0].includes(' › ') ? dim(`  via ${shorten(f.introducedBy[0])}`) : '')
        + (f.hooks.length ? red(`  [${f.hooks.join(',')}]`) : ''));
    }
    out.push('');
  }

  if (r.globals.length) {
    out.push(bold(red('Global installs')) + dim('  (these run with your shell privileges)'));
    for (const g of r.globals) {
      out.push(`  ${bold(g.root)}`);
      for (const h of g.hits) {
        const tag = h.severity === 'critical' ? red('critical') : blue('info    ');
        out.push(`  ${tag}  ${h.name}@${h.version}${h.hooks.length ? red(`  [${h.hooks.join(',')}]`) : ''}`);
      }
    }
    out.push('');
  }

  out.push(bold('Affected packages across the system'));
  for (const e of r.affectedPackages) {
    const tag = e.severity === 'critical' ? red('critical') : e.severity === 'warning' ? yellow('warning ') : blue('info    ');
    out.push(`  ${tag}  ${e.package}${e.version ? `@${e.version}` : ''}`
      + dim(`  ${e.locations.length} location${e.locations.length === 1 ? '' : 's'}`));
  }
  out.push('');
  out.push(bold('Summary'));
  out.push(`  ${red('critical')} ${r.counts.critical}   ${yellow('warning')} ${r.counts.warning}   ${blue('info')} ${r.counts.info}`
    + dim(`   across ${r.scanned.reposAffected} of ${r.scanned.reposFound} repos`));
  sysErrBlock();
  return out.join('\n');
}

// ---------------------------------------------------------------------------
// CSV report
// ---------------------------------------------------------------------------
const CSV_HEADER = ['kind', 'scope', 'package', 'version', 'severity', 'reach',
  'introduced_by', 'install_hooks', 'evidence', 'compromised_versions'];

function csvCell(v) {
  const s = v == null ? '' : String(v);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function csvRow(cells) {
  return cells.map(csvCell).join(',');
}

function findingCsvRow(kind, scope, f) {
  return csvRow([
    kind,
    scope,
    f.package,
    f.version || '',
    f.severity,
    f.direct ? 'direct' : 'transitive',
    (f.introducedBy || []).map((c) => shorten(c)).join(' | '),
    (f.hooks || []).join(';'),
    evidenceLines(f).join(' | '),
    (f.compromisedVersions || []).join(';'),
  ]);
}

function toCsv(result) {
  const rows = [csvRow(CSV_HEADER)];

  if (result.mode === 'system') {
    for (const s of result.repos) {
      for (const f of s.result.findings) rows.push(findingCsvRow('repo', s.root, f));
    }
    for (const g of result.globals) {
      for (const h of g.hits) {
        rows.push(csvRow([
          'global', g.root, h.name, h.version || '', h.severity, 'global',
          '', (h.hooks || []).join(';'), h.dir, versionsFor(h.name).join(';'),
        ]));
      }
    }
  } else {
    for (const f of result.findings) rows.push(findingCsvRow('project', result.root, f));
  }

  for (const e of result.errors || []) {
    rows.push(csvRow(['error', e.repo || result.root || '', '', '', 'error', '', '', '',
      `[${e.stage}] ${e.file || ''}: ${e.message}`, '']));
  }

  return `${rows.join('\r\n')}\r\n`;
}

// ---------------------------------------------------------------------------
// HTML report
// ---------------------------------------------------------------------------
const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
function esc(v) {
  return String(v == null ? '' : v).replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
}

const HTML_STYLE = `
  :root {
    --crit:#dc2626; --crit-bg:#fef2f2; --crit-line:#fecaca;
    --warn:#d97706; --warn-bg:#fffbeb; --warn-line:#fde68a;
    --info:#2563eb; --info-bg:#eff6ff; --info-line:#bfdbfe;
    --ok:#16a34a;   --ok-bg:#f0fdf4;   --ok-line:#bbf7d0;
    --ink:#1f2937; --muted:#6b7280; --line:#e5e7eb; --bg:#f9fafb; --card:#fff;
  }
  * { box-sizing: border-box; }
  body { margin:0; padding:2rem 1rem 4rem; background:var(--bg); color:var(--ink);
    font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
  .wrap { max-width:920px; margin:0 auto; }
  code, .mono { font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
  h1 { margin:0 0 .25rem; font-size:1.5rem; }
  h2 { font-size:1.05rem; margin:2rem 0 .75rem; }
  .banner { padding:1.25rem 1.5rem; border-radius:12px; margin-bottom:1.25rem; color:#fff; }
  .banner.crit { background:linear-gradient(135deg,#b91c1c,#dc2626); }
  .banner.warn { background:linear-gradient(135deg,#b45309,#d97706); }
  .banner.ok   { background:linear-gradient(135deg,#15803d,#16a34a); }
  .banner .status { margin:0; opacity:.95; }
  .meta { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:.6rem 1.5rem;
    background:var(--card); border:1px solid var(--line); border-radius:10px; padding:1rem 1.25rem; margin-bottom:1.25rem; }
  .meta .label { display:block; font-size:.72rem; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); margin-bottom:.15rem; }
  .warn-note { grid-column:1/-1; color:var(--warn); font-weight:600; }
  .summary-cards { display:flex; gap:.75rem; margin-bottom:1.5rem; }
  .card { flex:1; text-align:center; border-radius:10px; padding:1rem; border:1px solid var(--line); background:var(--card); }
  .card.crit { background:var(--crit-bg); border-color:var(--crit-line); }
  .card.warn { background:var(--warn-bg); border-color:var(--warn-line); }
  .card.info { background:var(--info-bg); border-color:var(--info-line); }
  .card .num { font-size:1.8rem; font-weight:700; }
  .card.crit .num { color:var(--crit); }
  .card.warn .num { color:var(--warn); }
  .card.info .num { color:var(--info); }
  .badge { display:inline-block; font-size:.68rem; font-weight:700; letter-spacing:.03em;
    padding:.15rem .5rem; border-radius:999px; margin-right:.5rem; vertical-align:middle; }
  .badge.critical { background:var(--crit-bg); color:var(--crit); border:1px solid var(--crit-line); }
  .badge.warning  { background:var(--warn-bg); color:var(--warn); border:1px solid var(--warn-line); }
  .badge.info     { background:var(--info-bg); color:var(--info); border:1px solid var(--info-line); }
  details.finding { border:1px solid var(--line); border-radius:8px; margin-bottom:.6rem; background:var(--card); }
  details.finding.critical { border-left:4px solid var(--crit); }
  details.finding.warning  { border-left:4px solid var(--warn); }
  details.finding.info     { border-left:4px solid var(--info); }
  details.finding summary { cursor:pointer; padding:.65rem .9rem; list-style:none; display:flex; align-items:center; gap:.5rem; flex-wrap:wrap; }
  details.finding summary::-webkit-details-marker { display:none; }
  .pkg { font-weight:600; font-family:ui-monospace,monospace; }
  .reach { font-size:.75rem; color:var(--muted); background:#f3f4f6; padding:.1rem .5rem; border-radius:999px; }
  .hooks { font-size:.75rem; color:#fff; background:var(--crit); padding:.1rem .5rem; border-radius:999px; }
  .finding-body { padding:0 .9rem .9rem; }
  .finding-body .why { color:var(--muted); margin:.25rem 0 .75rem; }
  .finding-body .label { display:block; font-size:.72rem; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); margin:.5rem 0 .25rem; }
  .finding-body ul { margin:.25rem 0; padding-left:1.1rem; }
  .finding-body li { margin:.15rem 0; word-break:break-all; }
  .muted { color:var(--muted); }
  table.rollup { width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line); border-radius:8px; overflow:hidden; }
  table.rollup th, table.rollup td { text-align:left; padding:.5rem .75rem; border-bottom:1px solid var(--line); }
  table.rollup tr:last-child td { border-bottom:none; }
  .repo-block { border:1px solid var(--line); border-radius:8px; margin-bottom:1rem; background:var(--card); }
  .repo-block > summary { cursor:pointer; padding:.75rem 1rem; font-weight:600; list-style:none; }
  .repo-block > summary::-webkit-details-marker { display:none; }
  .finding-list { padding:0 1rem 1rem; }
  .errbox { background:var(--warn-bg); border:1px solid var(--warn-line); border-radius:10px; padding:1rem 1.25rem; margin-top:1.25rem; }
  .errbox h2 { margin:0 0 .5rem; color:var(--warn); font-size:1rem; }
  .errbox li { word-break:break-all; }
  .clean { background:var(--ok-bg); border:1px solid var(--ok-line); color:#166534; padding:1rem 1.25rem; border-radius:10px; font-weight:600; }
  footer { text-align:center; color:var(--muted); font-size:.8rem; margin-top:3rem; }
`;

function htmlDocument(title, bodyHtml) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<style>${HTML_STYLE}</style>
</head>
<body>
<div class="wrap">
${bodyHtml}
<footer>Generated by chaindrop-scan · advisory ${esc(ADVISORY.id)} · ${esc(new Date().toISOString())}</footer>
</div>
</body>
</html>`;
}

function sevBadge(sev) {
  return `<span class="badge ${sev}">${esc(sev.toUpperCase())}</span>`;
}

function findingCardHtml(f) {
  const chains = (f.introducedBy || []).filter((c) => c.includes(' › '));
  const lines = evidenceLines(f);
  return `<details class="finding ${f.severity}" ${f.severity === 'critical' ? 'open' : ''}>
    <summary>
      ${sevBadge(f.severity)}
      <span class="pkg">${esc(f.package)}${f.version ? '@' + esc(f.version) : ''}</span>
      <span class="reach">${f.direct ? 'direct' : 'transitive'}</span>
      ${f.hooks.length ? `<span class="hooks">⚠ ${esc(f.hooks.join(', '))}</span>` : ''}
    </summary>
    <div class="finding-body">
      <p class="why">${esc(WHY[f.severity])}</p>
      ${chains.length ? `<div><span class="label">Introduced by</span><ul>${
        chains.slice(0, 5).map((c) => `<li><code>${esc(shorten(c))}</code></li>`).join('')
      }</ul>${chains.length > 5 ? `<p class="muted">… and ${chains.length - 5} more path(s)</p>` : ''}</div>` : ''}
      ${lines.length ? `<div><span class="label">Evidence</span><ul>${
        lines.map((l) => `<li><code>${esc(l)}</code></li>`).join('')
      }</ul></div>` : ''}
      ${f.compromisedVersions.length ? `<p><span class="label">Compromised versions</span> <code>${esc(f.compromisedVersions.join(', '))}</code></p>` : ''}
    </div>
  </details>`;
}

function globalHitHtml(h) {
  const cv = versionsFor(h.name);
  return `<details class="finding ${h.severity}" ${h.severity === 'critical' ? 'open' : ''}>
    <summary>
      ${sevBadge(h.severity)}
      <span class="pkg">${esc(h.name)}${h.version ? '@' + esc(h.version) : ''}</span>
      ${h.hooks.length ? `<span class="hooks">⚠ ${esc(h.hooks.join(', '))}</span>` : ''}
    </summary>
    <div class="finding-body">
      <p class="why">${esc(WHY[h.severity])}</p>
      <p><span class="label">Location</span> <code>${esc(h.dir)}</code></p>
      ${cv.length ? `<p><span class="label">Compromised versions</span> <code>${esc(cv.join(', '))}</code></p>` : ''}
    </div>
  </details>`;
}

function rollupTableHtml(list) {
  return `<table class="rollup"><thead><tr><th>Severity</th><th>Package</th><th>Version</th><th>Locations</th></tr></thead><tbody>
    ${list.map((e) => `<tr><td>${sevBadge(e.severity)}</td><td><code>${esc(e.package)}</code></td>`
      + `<td><code>${esc(e.version || '—')}</code></td><td>${e.locations.length}</td></tr>`).join('')}
  </tbody></table>`;
}

function errorsHtml(errors, withRepo) {
  if (!errors || !errors.length) return '';
  return `<section class="errbox"><h2>⚠ ${errors.length} scan warning(s) — results may be incomplete</h2><ul>${
    errors.slice(0, 20).map((e) => `<li><code>[${esc(e.stage)}] ${withRepo && e.repo ? esc(e.repo) + '/' : ''}${esc(e.file || '')}</code> ${esc(e.message)}</li>`).join('')
  }</ul>${errors.length > 20 ? `<p class="muted">… and ${errors.length - 20} more</p>` : ''}</section>`;
}

function renderHtml(result) {
  if (result.mode === 'system') return renderSystemHtml(result);
  const { root, advisory, scanned, counts, findings, durationMs } = result;
  const status = counts.critical ? 'crit' : counts.warning ? 'warn' : 'ok';
  const statusText = counts.critical ? 'Compromised packages detected'
    : counts.warning ? 'Potential exposure found — a declared range can resolve to a bad version'
      : 'No compromised packages found';

  const body = `
    <header class="banner ${status}"><h1>ChainDrop Scan Report</h1><p class="status">${esc(statusText)}</p></header>
    <section class="meta">
      <div><span class="label">Scanned</span><code>${esc(root)}</code></div>
      <div><span class="label">Advisory</span>${advisory.packages} packages / ${advisory.versions} compromised versions</div>
      <div><span class="label">Coverage</span>${scanned.lockfiles} lockfile(s), ${scanned.manifests} manifest(s), ${scanned.packagesInspected} packages inspected</div>
      <div><span class="label">Duration</span>${durationMs}ms</div>
    </section>
    <section class="summary-cards">
      <div class="card crit"><div class="num">${counts.critical}</div><div>Critical</div></div>
      <div class="card warn"><div class="num">${counts.warning}</div><div>Warning</div></div>
      <div class="card info"><div class="num">${counts.info}</div><div>Info</div></div>
    </section>
    ${findings.length
      ? `<section>${findings.map(findingCardHtml).join('')}</section>`
      : (result.errors && result.errors.length
        ? `<p class="errbox">No compromised packages found, but parts of this tree could not be fully scanned — this is NOT a verified-clean result.</p>`
        : `<p class="clean">✔ No ChainDrop-compromised packages found in this tree.</p>`)}
    ${errorsHtml(result.errors, false)}
  `;
  return htmlDocument('ChainDrop Scan Report', body);
}

function renderSystemHtml(result) {
  const { roots, scanned, counts, repos, globals, affectedPackages, durationMs } = result;
  const status = counts.critical ? 'crit' : counts.warning ? 'warn' : 'ok';
  const statusText = counts.critical ? 'Compromised packages detected on this system'
    : counts.warning ? 'Potential exposure found'
      : `No compromised packages found in ${scanned.reposFound} repositories`;

  const body = `
    <header class="banner ${status}"><h1>ChainDrop System Scan Report</h1><p class="status">${esc(statusText)}</p></header>
    <section class="meta">
      <div><span class="label">Roots</span><code>${esc(roots.join(', '))}</code></div>
      <div><span class="label">Repos</span>${scanned.reposFound} found, ${scanned.reposAffected} affected</div>
      <div><span class="label">Directories scanned</span>${scanned.directoriesSeen}</div>
      <div><span class="label">Packages inspected</span>${scanned.packagesInspected}</div>
      <div><span class="label">Duration</span>${(durationMs / 1000).toFixed(1)}s</div>
      ${scanned.truncated ? `<div class="warn-note">⚠ Stopped at the repo limit — this sweep is incomplete.</div>` : ''}
    </section>
    <section class="summary-cards">
      <div class="card crit"><div class="num">${counts.critical}</div><div>Critical</div></div>
      <div class="card warn"><div class="num">${counts.warning}</div><div>Warning</div></div>
      <div class="card info"><div class="num">${counts.info}</div><div>Info</div></div>
    </section>
    ${affectedPackages.length ? `<section><h2>Affected packages across the system</h2>${rollupTableHtml(affectedPackages)}</section>` : ''}
    ${repos.length ? `<section><h2>Repositories</h2>${repos.map((s) => `
      <details class="repo-block" open>
        <summary><code>${esc(s.root)}</code> <span class="muted">(${s.result.counts.critical} critical, ${s.result.counts.warning} warning, ${s.result.counts.info} info)</span></summary>
        <div class="finding-list">${s.result.findings.map(findingCardHtml).join('')}</div>
      </details>`).join('')}</section>` : ''}
    ${globals.length ? `<section><h2>Global installs</h2><p class="muted">These run with your shell privileges.</p>${globals.map((g) => `
      <details class="repo-block" open>
        <summary><code>${esc(g.root)}</code></summary>
        <div class="finding-list">${g.hits.map(globalHitHtml).join('')}</div>
      </details>`).join('')}</section>` : ''}
    ${!repos.length && !globals.length
      ? (result.errors && result.errors.length
        ? `<p class="errbox">No compromised packages found in ${scanned.reposFound} repositories, but some could not be fully scanned — this is NOT a verified-clean result.</p>`
        : `<p class="clean">✔ No ChainDrop-compromised packages found in ${scanned.reposFound} repositories or any global install location.</p>`)
      : ''}
    ${errorsHtml(result.errors, true)}
  `;
  return htmlDocument('ChainDrop System Scan Report', body);
}

// ---------------------------------------------------------------------------
// Embedded self-test (--selftest): fixtures for every supported format plus a
// regression test for each bug this scanner has fixed.
// ---------------------------------------------------------------------------
async function selfTest() {
  const os = require('os');
  let pass = 0;
  let fail = 0;
  const T = (name, cond, detail) => {
    if (cond) { pass++; process.stdout.write(`  ok  ${name}\n`); }
    else { fail++; process.stdout.write(`  FAIL ${name}${detail ? ` — ${detail}` : ''}\n`); }
  };
  const mk = (files) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'chaindrop-selftest-'));
    for (const [rel, content] of Object.entries(files)) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, typeof content === 'string' ? content : JSON.stringify(content));
    }
    return dir;
  };
  const F = (r, name, version) => r.findings.find((x) => x.package === name && (!version || x.version === version));

  // --- npm lockfile v3: transitive detection + chain ---
  const v3 = await scan(mk({
    'package.json': { name: 'app', dependencies: { wrap: '^1.0.0' } },
    'package-lock.json': {
      name: 'app', lockfileVersion: 3,
      packages: {
        '': { name: 'app', dependencies: { wrap: '^1.0.0' } },
        'node_modules/wrap': { version: '1.0.0', dependencies: { ecto: '5.0.1' } },
        'node_modules/ecto': { version: '5.0.1' },
      },
    },
  }));
  T('npm v3: transitive critical with chain', (() => {
    const f = F(v3, 'ecto');
    return f && f.severity === 'critical' && f.direct === false && /wrap@1\.0\.0.+ecto@5\.0\.1/.test(f.introducedBy[0]);
  })());

  // --- npm lockfile v2 (packages + legacy dependencies coexist) ---
  const v2 = await scan(mk({
    'package-lock.json': {
      name: 'v2app', lockfileVersion: 2,
      packages: {
        '': { name: 'v2app', dependencies: { wrap: '^1.0.0' } },
        'node_modules/wrap': { version: '1.0.0', dependencies: { ecto: '5.0.1' } },
        'node_modules/ecto': { version: '5.0.1' },
      },
      dependencies: { wrap: { version: '1.0.0', requires: { ecto: '5.0.1' } }, ecto: { version: '5.0.1' } },
    },
  }));
  T('npm v2: modern branch wins, no double-count', (() => {
    const f = F(v2, 'ecto');
    return f && f.severity === 'critical' && v2.scanned.packagesInspected === 3;
  })());

  // --- npm lockfile v1 (hoisted; requires gives real edges) ---
  const v1 = await scan(mk({
    'package-lock.json': {
      name: 'legacy', lockfileVersion: 1,
      dependencies: {
        alpha: { version: '1.2.0', requires: { 'creditcard.js': '2.1.8' } },
        'creditcard.js': { version: '2.1.8' },
      },
    },
  }));
  T('npm v1: hoisted transitive attributed via requires', (() => {
    const f = F(v1, 'creditcard.js');
    return f && f.severity === 'critical' && f.direct === false && /alpha@1\.2\.0/.test(f.introducedBy[0]);
  })());

  // --- npm-shrinkwrap.json is scanned like a lockfile ---
  const shrink = await scan(mk({
    'npm-shrinkwrap.json': {
      name: 'sw', lockfileVersion: 3,
      packages: { '': { name: 'sw' }, 'node_modules/keyv': { version: '6.0.0' } },
    },
  }));
  T('shrinkwrap: parsed as lockfile', !!F(shrink, 'keyv', '6.0.0'));

  // --- yarn classic v1 ---
  const y1 = await scan(mk({
    'yarn.lock': `# yarn lockfile v1

wrapper@^1.0.0:
  version "1.3.0"
  dependencies:
    "@qlik/sdk" "0.28.1"

"@qlik/sdk@0.28.1":
  version "0.28.1"
`,
  }));
  T('yarn v1: descriptor resolution + transitive', (() => {
    const f = F(y1, '@qlik/sdk');
    return f && f.version === '0.28.1' && f.direct === false;
  })());

  // --- yarn Berry v4/v8+: quoted multi-descriptor header, workspace root,
  //     npm: protocol dep ranges, patch: name extraction ---
  const berry = await scan(mk({
    'yarn.lock': `# This file is generated by running "yarn install" inside your project.

__metadata:
  version: 8
  cacheKey: 10

"myapp@workspace:.":
  version: 0.0.0-use.local
  resolution: "myapp@workspace:."
  dependencies:
    liba: "npm:^1.0.0"
    libb: "npm:^2.0.0"
  languageName: unknown
  linkType: soft

"liba@npm:^1.0.0, liba@npm:^1.2.0":
  version: 1.2.3
  resolution: "liba@npm:1.2.3"
  dependencies:
    "@qlik/sdk": "npm:0.28.1"
    typescript: "patch:typescript@npm%3A5.0.4#optional!builtin<compat/typescript>"
  languageName: node
  linkType: hard

"libb@npm:^2.0.0":
  version: 2.0.0
  resolution: "libb@npm:2.0.0"
  dependencies:
    liba: "npm:^1.2.0"
  languageName: node
  linkType: hard

"@qlik/sdk@npm:0.28.1":
  version: 0.28.1
  resolution: "@qlik/sdk@npm:0.28.1"
  languageName: node
  linkType: hard

"typescript@patch:typescript@npm%3A5.0.4#optional!builtin<compat/typescript>":
  version: 5.0.4
  resolution: "typescript@patch:typescript@npm%3A5.0.4#compat::version=5.0.4&hash=abc"
  languageName: node
  linkType: hard
`,
  }));
  T('yarn berry: workspace-rooted transitive chain', (() => {
    const f = F(berry, '@qlik/sdk');
    return f && f.direct === false && /^myapp › liba@1\.2\.3 › @qlik\/sdk@0\.28\.1$/.test(f.introducedBy[0]);
  })(), JSON.stringify((F(berry, '@qlik/sdk') || {}).introducedBy));
  T('yarn berry: multi-descriptor split links second range', berry.errors.length === 0 && berry.scanned.packagesInspected === 5);

  // --- pnpm v5: slash keys, underscore peer suffixes, specifiers block ---
  const p5 = await scan(mk({
    'pnpm-lock.yaml': `lockfileVersion: 5.4

importers:

  .:
    specifiers:
      outer: ^1.0.0
    dependencies:
      outer: 1.4.0_react@17.0.2

packages:

  /outer/1.4.0_react@17.0.2:
    resolution: {integrity: sha512-a}
    dependencies:
      intercom-client: 7.0.4

  /intercom-client/7.0.4:
    resolution: {integrity: sha512-b}
`,
  }));
  T('pnpm v5: underscore peer suffix stripped, chain intact', (() => {
    const f = F(p5, 'intercom-client');
    return f && f.severity === 'critical' && f.direct === false && /outer@1\.4\.0 › intercom-client@7\.0\.4/.test(f.introducedBy[0]);
  })(), JSON.stringify((F(p5, 'intercom-client') || {}).introducedBy));

  // --- pnpm v6: /name@version keys ---
  const p6 = await scan(mk({
    'pnpm-lock.yaml': `lockfileVersion: '6.0'

importers:

  .:
    dependencies:
      outer:
        specifier: ^1.0.0
        version: 1.4.0

packages:

  /outer@1.4.0:
    resolution: {integrity: sha512-a}
    dependencies:
      leo-aws: 2.0.4

  /leo-aws@2.0.4:
    resolution: {integrity: sha512-b}
`,
  }));
  T('pnpm v6: at-form keys resolve', (() => {
    const f = F(p6, 'leo-aws');
    return f && f.severity === 'critical' && f.direct === false;
  })());

  // --- pnpm v9: snapshots section ---
  const p9 = await scan(mk({
    'pnpm-lock.yaml': `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      outer:
        specifier: ^1.0.0
        version: 1.4.0

packages:

  outer@1.4.0:
    resolution: {integrity: sha512-a}

  mountly@0.2.2:
    resolution: {integrity: sha512-b}

snapshots:

  outer@1.4.0:
    dependencies:
      mountly: 0.2.2

  mountly@0.2.2: {}
`,
  }));
  T('pnpm v9: snapshot edges resolve', (() => {
    const f = F(p9, 'mountly');
    return f && f.severity === 'critical' && f.direct === false;
  })());

  // --- unsupported lockfile: must surface an error, never a silent clean ---
  const bun = await scan(mk({
    'package.json': { name: 'bunapp' },
    'bun.lock': '{}',
  }));
  T('bun.lock: reported as unsupported, not silent-clean',
    bun.errors.length === 1 && /unsupported/.test(bun.errors[0].message));

  // --- broken lockfile: error surfaced AND manifest evidence still collected ---
  const broken = await scan(mk({
    'package.json': { name: 'b', dependencies: { keyv: '^6.0.0' } },
    'package-lock.json': '{ definitely not json',
  }));
  T('broken lockfile: parse error surfaced', broken.errors.some((e) => e.stage === 'parse'));
  T('broken lockfile: manifest findings survive', (() => {
    const f = F(broken, 'keyv');
    return f && f.severity === 'warning';
  })());

  // --- attribution: a safe declared range must not mark a transitive bad
  //     version as direct (the merge/directness regression) ---
  const attr = await scan(mk({
    'package.json': { name: 'root', dependencies: { ecto: '^4.0.0', lib: '^1.0.0' } },
    'package-lock.json': {
      name: 'root', lockfileVersion: 3,
      packages: {
        '': { name: 'root', dependencies: { ecto: '^4.0.0', lib: '^1.0.0' } },
        'node_modules/ecto': { version: '4.0.0' },
        'node_modules/lib': { version: '1.0.0', dependencies: { ecto: '5.0.1' } },
        'node_modules/lib/node_modules/ecto': { version: '5.0.1' },
      },
    },
  }));
  T('attribution: transitive bad version stays transitive', (() => {
    const f = F(attr, 'ecto', '5.0.1');
    return f && f.severity === 'critical' && f.direct === false;
  })(), JSON.stringify(F(attr, 'ecto', '5.0.1')));
  T('attribution: declared safe version stays direct+info', (() => {
    const f = F(attr, 'ecto', '4.0.0');
    return f && f.severity === 'info' && f.direct === true;
  })());

  // --- npm workspaces: workspace-declared dep is direct, its transitives are not ---
  const mono = await scan(mk({
    'package.json': { name: 'mono', workspaces: ['pkgs/*'] },
    'pkgs/a/package.json': { name: 'a', version: '1.0.0', dependencies: { libx: '^1.0.0' } },
    'package-lock.json': {
      name: 'mono', lockfileVersion: 3,
      packages: {
        '': { name: 'mono' },
        'pkgs/a': { name: 'a', version: '1.0.0', dependencies: { libx: '^1.0.0' } },
        'node_modules/a': { link: true, resolved: 'pkgs/a' },
        'node_modules/libx': { version: '1.0.0', dependencies: { ecto: '5.0.1' } },
        'node_modules/ecto': { version: '5.0.1' },
      },
    },
  }));
  T('workspaces: transitive under a workspace stays transitive', (() => {
    const f = F(mono, 'ecto', '5.0.1');
    return f && f.direct === false && /a › libx@1\.0\.0 › ecto@5\.0\.1/.test(f.introducedBy[0]);
  })(), JSON.stringify((F(mono, 'ecto', '5.0.1') || {}).introducedBy));

  // --- ignore applied during scanning, counts consistent ---
  const ign = await scan(mk({
    'package-lock.json': {
      name: 'i', lockfileVersion: 3,
      packages: { '': { name: 'i' }, 'node_modules/keyv': { version: '6.0.0' }, 'node_modules/ecto': { version: '5.0.1' } },
    },
  }), { ignoreSet: new Set(['keyv']) });
  T('--ignore: skipped at scan time, counts consistent',
    !F(ign, 'keyv') && !!F(ign, 'ecto') && ign.counts.critical === 1);

  // --- BFS path cache: repeated findings share one traversal, chains stay shortest ---
  const deepPkgs = { '': { name: 'deep', dependencies: { 'p-0': '1.0.0' } } };
  for (let i = 0; i < 50; i++) {
    deepPkgs[`node_modules/p-${i}`] = { version: '1.0.0', dependencies: i < 49 ? { [`p-${i + 1}`]: '1.0.0' } : { keyv: '6.0.0', ecto: '5.0.1' } };
  }
  deepPkgs['node_modules/keyv'] = { version: '6.0.0' };
  deepPkgs['node_modules/ecto'] = { version: '5.0.1' };
  const deep = await scan(mk({ 'package-lock.json': { name: 'deep', lockfileVersion: 3, packages: deepPkgs } }));
  T('BFS: 50-deep chains resolved for multiple findings', (() => {
    const a = F(deep, 'keyv');
    const b = F(deep, 'ecto');
    return a && b && a.introducedBy[0].split(' › ').length === 52 && b.introducedBy[0].split(' › ').length === 52;
  })());

  // --- clean tree: pure checkmark only when zero errors ---
  const clean = await scan(mk({
    'package.json': { name: 'c', dependencies: { lodash: '^4.17.21' } },
    'package-lock.json': { name: 'c', lockfileVersion: 3, packages: { '': { name: 'c' }, 'node_modules/lodash': { version: '4.17.21' } } },
  }));
  T('clean: zero findings, zero errors', clean.findings.length === 0 && clean.errors.length === 0);

  process.stdout.write(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
const FORMATS = new Set(['text', 'json', 'html', 'csv']);

const HELP = `
chaindrop-scan — find npm packages compromised by the ChainDrop worm,
including transitive dependencies.

  node index.js [path] [options]           scan one project
  node index.js --system                   scan every repo on this machine

  --system, -a         sweep the whole system: every repo plus global installs
  --roots <dirs>       comma-separated roots for --system (default: home + /srv,/opt,...)
  --max-repos <n>      stop after this many repos          (default: 5000)
  --concurrency <n>    repos scanned in parallel in --system mode (default: 6)
  --no-globals         skip global install locations
  -f, --format <fmt>   text | json | html | csv             (default: text)
  --json               shorthand for --format json
  -o, --output <file>  write the report to a file instead of stdout
                        (html defaults to chaindrop-report.html if no -o given)
  --fail-on <level>    critical | warning | none            (default: warning)
  --ignore <pkgs>      comma-separated names to skip
  --no-node-modules    lockfiles and manifests only (much faster sweep)
  --database <file>    use an updated advisory JSON instead of the bundled snapshot
  --serve [port]       run a local dashboard at http://127.0.0.1:<port> (default 4879)
  --no-progress        disable the live terminal progress line
  --selftest           run the embedded test suite (every lockfile format) and exit
  --list               print the advisory database
  -q, --quiet          print only when something is found
  -h, --help           this text

Exit: 0 clean · 1 findings at or above --fail-on · 2 error
`;

/** Renders `result` in the requested format and writes it to a file or stdout. */
async function writeReport(result, opts) {
  const format = opts.format || 'text';
  const isSystem = result.mode === 'system';

  let content;
  if (format === 'json') content = JSON.stringify(result, null, 2);
  else if (format === 'csv') content = toCsv(result);
  else if (format === 'html') content = isSystem ? renderSystemHtml(result) : renderHtml(result);
  else content = isSystem ? reportSystem(result) : report(result);

  let outPath = opts.output;
  if (format === 'html' && !outPath) {
    outPath = isSystem ? 'chaindrop-system-report.html' : 'chaindrop-report.html';
  }

  if (outPath) {
    await fsp.writeFile(outPath, content, 'utf8');
    process.stdout.write(`${format} report written to ${path.resolve(outPath)}\n`);
  } else {
    process.stdout.write(`${content}\n`);
  }
}

// ---------------------------------------------------------------------------
// Local dashboard (--serve): a zero-dependency HTTP server, bound to
// 127.0.0.1 only, that runs scans on demand and streams live progress to the
// browser over Server-Sent Events. The final report reuses the exact same
// renderHtml/renderSystemHtml used by `-f html`, so the dashboard and the
// saved report are always identical.
// ---------------------------------------------------------------------------
function dashboardHtml() {
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>chaindrop-scan</title>
<style>
  :root { --bg:#0b0f14; --panel:#121822; --line:#232c39; --text:#e6edf3; --muted:#8b96a5;
    --accent:#4f9dff; --ok:#3fb950; --warn:#d29922; --crit:#f85149; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif; }
  header { padding:1.5rem 2rem 1rem; border-bottom:1px solid var(--line); }
  header h1 { margin:0; font-size:1.25rem; }
  header p { margin:.35rem 0 0; color:var(--muted); font-size:.9rem; }
  main { max-width:1000px; margin:0 auto; padding:1.5rem 2rem 4rem; }
  .panel { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:1.25rem; }
  .row { display:flex; gap:.75rem; flex-wrap:wrap; align-items:center; }
  .row + .row { margin-top:.75rem; }
  label { color:var(--muted); font-size:.85rem; }
  input[type=text] { flex:1; min-width:220px; background:#0e141c; border:1px solid var(--line); color:var(--text);
    padding:.55rem .7rem; border-radius:6px; font:inherit; }
  input[type=checkbox] { accent-color:var(--accent); }
  button { background:var(--accent); color:#04101f; border:none; padding:.6rem 1.1rem; border-radius:6px;
    font:inherit; font-weight:600; cursor:pointer; }
  button:disabled { opacity:.5; cursor:default; }
  button.secondary { background:transparent; border:1px solid var(--line); color:var(--text); font-weight:500; }
  .log { margin-top:1rem; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:.85rem;
    color:var(--muted); min-height:1.4em; white-space:pre-wrap; word-break:break-all; }
  .log.busy::before { content:"● "; color:var(--accent); animation:pulse 1s ease-in-out infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.25} }
  .log.err { color:var(--crit); }
  #resultWrap { margin-top:1.5rem; display:none; }
  #resultWrap.show { display:block; }
  iframe { width:100%; height:75vh; border:1px solid var(--line); border-radius:10px; background:#fff; }
  .hint { color:var(--muted); font-size:.8rem; margin-top:.5rem; }
</style>
</head>
<body>
<header>
  <h1>chaindrop-scan</h1>
  <p>Local dashboard — scans run on this machine only; nothing here touches the network.</p>
</header>
<main>
  <div class="panel">
    <div class="row">
      <label for="path" style="min-width:5em">Path</label>
      <input id="path" type="text" value="." placeholder="/path/to/project">
      <label><input id="system" type="checkbox"> Scan entire system</label>
    </div>
    <div class="row" id="rootsRow" style="display:none">
      <label for="roots" style="min-width:5em">Roots</label>
      <input id="roots" type="text" placeholder="optional, comma-separated (defaults to home dirs)">
    </div>
    <div class="row">
      <label for="ignore" style="min-width:5em">Ignore</label>
      <input id="ignore" type="text" placeholder="optional, comma-separated package names">
    </div>
    <div class="row">
      <button id="go">Scan</button>
      <button id="stop" class="secondary" style="display:none">Cancel</button>
      <span class="hint" id="advisoryLine"></span>
    </div>
    <div class="log" id="log"></div>
  </div>
  <div id="resultWrap">
    <iframe id="resultFrame" title="scan report"></iframe>
  </div>
</main>
<script>
(function () {
  const $ = (id) => document.getElementById(id);
  const systemBox = $('system'), rootsRow = $('rootsRow'), pathInput = $('path');
  systemBox.addEventListener('change', () => {
    rootsRow.style.display = systemBox.checked ? 'flex' : 'none';
    pathInput.disabled = systemBox.checked;
  });

  fetch('/api/info').then((r) => r.json()).then((info) => {
    $('advisoryLine').textContent = info.advisory.packages + ' packages / ' + info.advisory.versions + ' compromised versions tracked';
  }).catch(() => {});

  let es = null;
  const go = $('go'), stop = $('stop'), log = $('log'), wrap = $('resultWrap'), frame = $('resultFrame');

  function reset() {
    log.className = 'log';
    log.textContent = '';
    wrap.classList.remove('show');
    frame.srcdoc = '';
  }

  function startScan() {
    reset();
    const params = new URLSearchParams();
    if (systemBox.checked) {
      params.set('system', '1');
      const roots = $('roots').value.trim();
      if (roots) params.set('roots', roots);
    } else {
      params.set('path', pathInput.value.trim() || '.');
    }
    const ignore = $('ignore').value.trim();
    if (ignore) params.set('ignore', ignore);

    go.disabled = true;
    stop.style.display = 'inline-block';
    log.classList.add('busy');
    log.textContent = 'starting…';

    es = new EventSource('/api/scan?' + params.toString());

    es.addEventListener('progress', (ev) => {
      const e = JSON.parse(ev.data);
      log.textContent = describe(e);
    });
    es.addEventListener('done', (ev) => {
      finish();
      const html = atob(ev.data);
      frame.srcdoc = html;
      wrap.classList.add('show');
      log.classList.remove('busy');
      log.textContent = 'done';
    });
    es.addEventListener('error', (ev) => {
      finish();
      log.classList.remove('busy');
      log.classList.add('err');
      try { log.textContent = 'Error: ' + JSON.parse(ev.data).message; }
      catch { log.textContent = 'Connection lost.'; }
    });
  }

  function finish() {
    if (es) { es.close(); es = null; }
    go.disabled = false;
    stop.style.display = 'none';
  }

  function describe(e) {
    switch (e.phase) {
      case 'discover': return 'discovering files…';
      case 'discovered': return 'found ' + e.lockfiles + ' lockfile(s), ' + e.manifests + ' manifest(s), ' + e.nodeModules + ' node_modules dir(s)';
      case 'lockfile': return 'parsing lockfiles ' + e.current + '/' + e.total + '  ' + e.file;
      case 'nodeModules': return 'scanning node_modules ' + e.current + '/' + e.total + '  ' + e.dir;
      case 'system-discover': return 'discovering repositories…';
      case 'system-discovered': return 'found ' + e.repos + ' repo(s), scanning…';
      case 'system-repo': return 'scanning repos ' + e.current + '/' + e.total + '  ' + e.repo;
      case 'system-globals': return 'scanning global installs ' + e.current + '/' + e.total;
      default: return e.phase || '';
    }
  }

  go.addEventListener('click', startScan);
  stop.addEventListener('click', () => { finish(); log.classList.remove('busy'); log.textContent = 'cancelled'; });
  pathInput.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') startScan(); });
})();
</script>
</body>
</html>`;
}

async function startServer(opts, defaultPath) {
  const http = require('http');
  const { URL } = require('url');
  const port = opts.servePort || 4879;

  const server = http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://127.0.0.1');

    if (u.pathname === '/' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(dashboardHtml());
      return;
    }

    if (u.pathname === '/api/info' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ advisory: { id: ADVISORY.id, packages: INDEX.size, versions: ADVISORY.versionCount, source: ADVISORY.source } }));
      return;
    }

    if (u.pathname === '/api/scan' && req.method === 'GET') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
      });
      const send = (event, data) => res.write(`event: ${event}\ndata: ${data}\n\n`);
      const ignoreSet = new Set((u.searchParams.get('ignore') || '').split(',').map((x) => x.trim()).filter(Boolean));
      const scanOpts = { ignoreSet, onProgress: (e) => send('progress', JSON.stringify(e)) };

      try {
        let result;
        if (u.searchParams.get('system') === '1') {
          const rootsParam = (u.searchParams.get('roots') || '').split(',').map((x) => x.trim()).filter(Boolean);
          result = await scanSystem(rootsParam.length ? rootsParam : defaultRoots(), scanOpts);
        } else {
          result = await scan(u.searchParams.get('path') || defaultPath, scanOpts);
        }
        const html = result.mode === 'system' ? renderSystemHtml(result) : renderHtml(result);
        send('done', Buffer.from(html, 'utf8').toString('base64'));
      } catch (err) {
        send('error', JSON.stringify({ message: err && err.message ? err.message : String(err) }));
      } finally {
        res.end();
      }
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });

  process.stdout.write(`chaindrop-scan dashboard running at http://127.0.0.1:${port}\nPress Ctrl+C to stop.\n`);
}

async function main() {
  const argv = process.argv.slice(2);
  const opts = { failOn: 'warning', ignore: [], format: 'text' };
  let root = null;
  let roots = null;

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') { process.stdout.write(HELP); return; }
    else if (a === '--list') {
      for (const [n, v] of INDEX) process.stdout.write(`${n} ${[...v].join(' ')}\n`);
      return;
    } else if (a === '--selftest') { return selfTest(); }
    else if (a === '--database') { try { loadDatabase(argv[++i]); } catch (err) { process.stderr.write(`Failed to load database: ${err.message}\n`); process.exit(2); } }
    else if (a === '--system' || a === '-a' || a === '--all') opts.system = true;
    else if (a === '--roots') { roots = (argv[++i] || '').split(',').map((x) => x.trim()).filter(Boolean); opts.system = true; }
    else if (a === '--max-repos') opts.maxRepos = parseInt(argv[++i], 10);
    else if (a === '--concurrency') opts.concurrency = parseInt(argv[++i], 10);
    else if (a === '--no-globals') opts.globals = false;
    else if (a === '--json') opts.format = 'json';
    else if (a === '-f' || a === '--format') opts.format = argv[++i];
    else if (a === '-o' || a === '--output') opts.output = argv[++i];
    else if (a === '-q' || a === '--quiet') opts.quiet = true;
    else if (a === '--no-node-modules') opts.nodeModules = false;
    else if (a === '--fail-on') opts.failOn = argv[++i];
    else if (a === '--ignore') opts.ignore = (argv[++i] || '').split(',').map((x) => x.trim()).filter(Boolean);
    else if (a === '--no-progress') opts.progress = false;
    else if (a === '--serve') {
      opts.serve = true;
      if (argv[i + 1] && /^\d+$/.test(argv[i + 1])) opts.servePort = parseInt(argv[++i], 10);
    }
    else if (a.startsWith('-')) { process.stderr.write(`Unknown option: ${a}\n${HELP}`); process.exit(2); }
    else root = a;
  }

  if (!FORMATS.has(opts.format)) {
    process.stderr.write(`Invalid --format: ${opts.format} (expected text, json, html or csv)\n`);
    process.exit(2);
  }
  const threshold = opts.failOn === 'none' ? Infinity : RANK[opts.failOn];
  if (threshold === undefined) { process.stderr.write(`Invalid --fail-on: ${opts.failOn}\n`); process.exit(2); }
  opts.ignoreSet = new Set(opts.ignore);

  if (opts.serve) {
    return startServer(opts, root || process.cwd());
  }

  // Live progress line in the terminal, active by default whenever stderr is
  // a TTY and the output format is human-readable. One line is overwritten
  // in place rather than scrolling, and is cleared before the final report
  // is printed so it never gets mixed into piped/redirected output.
  // Progress writes only to stderr, which is a separate stream from the
  // report itself — so it's safe to show for every output format, not just
  // text. It only needs stderr to actually be a terminal.
  const ttyProgress = opts.progress !== false && process.stderr.isTTY;
  const started = Date.now();
  let lastLabel = '';
  let lastPath = '';

  // The status line must never exceed the terminal width. If it wraps, the
  // carriage return only rewinds the final visual row and every earlier row
  // is left stranded on screen — which looks exactly like a frozen scan
  // spewing duplicate lines. Long paths are trimmed from the left so the
  // most specific part (the tail) stays visible.
  const fit = (label, p) => {
    const width = (process.stderr.columns || 80) - 1;
    if (!p) return label.slice(0, width);
    const room = width - label.length - 2;
    if (room < 12) return label.slice(0, width);
    const short = p.length <= room ? p : `…${p.slice(-(room - 1))}`;
    return `${label}  ${short}`;
  };

  const draw = () => {
    if (!ttyProgress) return;
    const secs = Math.floor((Date.now() - started) / 1000);
    // Elapsed time only appears once a scan is slow enough to look stuck.
    const label = secs >= 3 ? `[${secs}s] ${lastLabel}` : lastLabel;
    process.stderr.write(`\r\u001b[K${fit(label, lastPath)}`);
  };

  const printLine = (label, p = '') => { lastLabel = label; lastPath = p; draw(); };

  // Repaint on a timer so the elapsed counter keeps moving even while a
  // single huge directory is being walked and no new events arrive.
  const heartbeat = ttyProgress ? setInterval(draw, 1000) : null;
  if (heartbeat && heartbeat.unref) heartbeat.unref();
  opts.stopProgress = () => { if (heartbeat) clearInterval(heartbeat); };

  opts.onProgress = (e) => {
    if (e.phase === 'discover') printLine('discovering files…');
    else if (e.phase === 'walk') printLine(`walking directories (${e.dirsSeen} seen)`, e.dir);
    else if (e.phase === 'discovered') printLine(`found ${e.lockfiles} lockfile(s), ${e.manifests} manifest(s), ${e.nodeModules} node_modules dir(s)`);
    else if (e.phase === 'lockfile') printLine(`parsing lockfiles ${e.current}/${e.total}`, e.file);
    else if (e.phase === 'nodeModules') printLine(`scanning node_modules ${e.current}/${e.total}`, e.dir);
    else if (e.phase === 'system-discover') printLine('discovering repositories…');
    else if (e.phase === 'system-discovered') printLine(`found ${e.repos} repo(s), scanning…`);
    else if (e.phase === 'system-repo') printLine(`scanning repos ${e.current}/${e.total}`, e.repo);
    else if (e.phase === 'system-globals') printLine(`scanning global installs ${e.current}/${e.total}`);
  };

  if (opts.system) {
    const result = await scanSystem(roots || (root ? [root] : defaultRoots()), opts);

    // -q only mutes a clean *text* report: machine formats always emit a
    // document, and scan errors always surface — a repo that failed to parse
    // must never be silenced into looking clean.
    if (opts.stopProgress) opts.stopProgress();
    if (opts.stopProgress) opts.stopProgress();
  if (ttyProgress) process.stderr.write('\r\u001b[K');
    if (!opts.quiet || result.affectedPackages.length || result.errors.length || opts.format !== 'text') await writeReport(result, opts);
    process.exit(result.affectedPackages.some((e) => RANK[e.severity] >= threshold) ? 1 : 0);
  }

  const result = await scan(root || process.cwd(), opts);

  if (opts.stopProgress) opts.stopProgress();
  if (ttyProgress) process.stderr.write('\r\u001b[K');
  if (!opts.quiet || result.findings.length || result.errors.length || opts.format !== 'text') await writeReport(result, opts);
  process.exit(result.findings.some((f) => RANK[f.severity] >= threshold) ? 1 : 0);
}

if (require.main === module) {
  main().catch((err) => {
    process.stderr.write(`chaindrop-scan failed: ${err && err.stack ? err.stack : err}\n`);
    process.exit(2);
  });
}

module.exports = {
  scan, scanSystem, findRepos, globalRoots, check, satisfies, loadDatabase, ADVISORY,
  report, reportSystem, renderHtml, renderSystemHtml, toCsv, selfTest,
};
