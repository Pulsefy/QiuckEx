import React from 'react';
import render from 'react-test-renderer';
import HomeScreen from '../app/index';

describe('<HomeScreen />', () => {
    it('renders correctly', () => {
        let tree: ReturnType<typeof render.create>;
        render.act(() => {
            tree = render.create(<HomeScreen />);
        });

        // @ts-expect-error tree is assigned inside act
        const json = tree.toJSON();
        expect(json).toBeDefined();
    });
});
