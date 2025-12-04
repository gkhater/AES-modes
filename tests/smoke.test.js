import { jsx as _jsx } from "react/jsx-runtime";
import { render, screen } from '@testing-library/react';
import App from '../src/App';
describe('App scaffold', function () {
    it('renders the placeholder shell', function () {
        render(_jsx(App, {}));
        expect(screen.getByText(/Project setup complete/i)).toBeInTheDocument();
    });
});
