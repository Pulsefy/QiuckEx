import React from 'react';
import renderer, { act } from 'react-test-renderer';
import { Text, TouchableOpacity } from 'react-native';

import { ForceUpgradeGate } from '../components/ForceUpgradeGate';
import { VersionCheckService } from '../services/VersionCheckService';

jest.mock('../components/ReleaseNotes', () => {
  const React = require('react');
  const { Text, TouchableOpacity, View } = require('react-native');

  return {
    ReleaseNotes: ({ visible, onClose }: { visible: boolean; onClose: () => void }) =>
      visible
        ? React.createElement(
            View,
            null,
            React.createElement(Text, null, 'New Version Available'),
            React.createElement(TouchableOpacity, { onPress: onClose }, React.createElement(Text, null, 'Later')),
          )
        : null,
  };
});

jest.mock('../services/VersionCheckService', () => ({
  VersionCheckService: {
    checkVersion: jest.fn(),
  },
}));

describe('ForceUpgradeGate', () => {
  it('blocks unsupported versions with a clear update message', async () => {
    (VersionCheckService.checkVersion as jest.Mock).mockResolvedValue({
      status: 'force_upgrade',
      latestVersion: '1.4.0',
      releaseNotes: ['Security fixes'],
      storeUrl: 'https://apps.apple.com/app/quickex',
      message: 'Version 1.0.0 is no longer supported. Update to continue.',
    });

    let tree: renderer.ReactTestRenderer;
    await act(async () => {
      tree = renderer.create(
        <ForceUpgradeGate>
          <Text>App content</Text>
        </ForceUpgradeGate>,
      );
    });

    const text = tree!.root.findAllByType(Text).map((node) => node.props.children).flat().join(' ');
    expect(text).toContain('Update Required');
    expect(text).toContain('no longer supported');
    expect(text).not.toContain('App content');
  });

  it('shows a dismissible optional upgrade prompt', async () => {
    (VersionCheckService.checkVersion as jest.Mock).mockResolvedValue({
      status: 'optional_upgrade',
      latestVersion: '1.4.0',
      releaseNotes: ['Recommended update'],
      storeUrl: 'https://apps.apple.com/app/quickex',
      message: 'Version 1.4.0 is recommended.',
    });

    let tree: renderer.ReactTestRenderer;
    await act(async () => {
      tree = renderer.create(
        <ForceUpgradeGate>
          <Text>App content</Text>
        </ForceUpgradeGate>,
      );
    });

    expect(tree!.root.findAllByType(Text).map((node) => node.props.children).flat().join(' ')).toContain('New Version Available');

    const laterButton = tree!.root.findAllByType(TouchableOpacity)[0];
    await act(async () => {
      laterButton.props.onPress();
    });

    const textAfterDismiss = tree!.root.findAllByType(Text).map((node) => node.props.children).flat().join(' ');
    expect(textAfterDismiss).toContain('App content');
    expect(textAfterDismiss).not.toContain('New Version Available');
  });
});
