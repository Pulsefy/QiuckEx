import React from 'react';
import renderer, { act } from 'react-test-renderer';
import HomeScreen from '../app/index';
import { NotificationProvider } from '../components/notifications/NotificationContext';

describe('<HomeScreen />', () => {
    it('renders correctly', () => {
        let tree: any;
        act(() => {
            tree = renderer.create(
                <NotificationProvider>
                    <HomeScreen />
                </NotificationProvider>
            ).toJSON();
        });
        expect(tree).toBeDefined();
    });
});
