import './App.css';

function App() {
  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand">
          <span className="brand-mark">AES</span>
          <span className="brand-text">Modes Playground</span>
        </div>
        <p className="tagline">Scaffold ready – implementation coming next</p>
      </header>
      <main className="app-main">
        <section className="card">
          <h1>Project setup complete</h1>
          <p>
            The AES core, mode adapters, tests, and UI will be added step by step. This build is a clean
            foundation with React, Vite, TypeScript, ESLint, Vitest, and Testing Library.
          </p>
        </section>
      </main>
    </div>
  );
}

export default App;
