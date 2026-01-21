import React from 'react';
import render from 'react-test-renderer';
import HomeScreen from '../app/index';

describe('<HomeScreen />', () => {
    it('renders correctly', () => {
        const tree = render.create(<HomeScreen />).toJSON();
        expect(tree).toBeDefined();
    });
});
