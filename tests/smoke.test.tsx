import { render, screen } from '@testing-library/react';
import App from '../src/App';

describe('App scaffold', () => {
  it('renders the placeholder shell', () => {
    render(<App />);
    expect(screen.getByText(/Modes Playground/i)).toBeInTheDocument();
  });
});
