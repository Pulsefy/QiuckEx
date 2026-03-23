const { getDefaultConfig } = require('expo/metro-config');
const exclusionList = require('metro-config/src/defaults/exclusionList');
const path = require('path');

const projectRoot = __dirname;
const parentNodeModules = path.resolve(__dirname, '..', 'node_modules');
const parentNodeModulesRegex = new RegExp(`^${parentNodeModules.replace(/\\\\/g, '\\\\\\\\')}`);

// Export synchronously to avoid Metro using dynamic ESM import on Windows
const config = getDefaultConfig(projectRoot) || {};
config.watchFolders = [projectRoot];
config.resolver = config.resolver || {};
config.resolver.blockList = exclusionList([parentNodeModulesRegex]);

module.exports = config;
