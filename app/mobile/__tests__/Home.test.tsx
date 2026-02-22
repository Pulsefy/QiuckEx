import React from 'react';
import renderer, { act } from 'react-test-renderer';
import HomeScreen from '../app/index';

describe('<HomeScreen />', () => {
    it('renders correctly', () => {
        let tree: any;
        act(() => {
            tree = renderer.create(<HomeScreen />).toJSON();
        });
        expect(tree).toBeDefined();
    });
});
