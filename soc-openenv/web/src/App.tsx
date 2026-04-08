import { NavLink, Route, Routes } from "react-router-dom";
import HomePage from "./components/HomePage";
import AboutPage from "./components/AboutPage";

function App() {
  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-block">
          <p className="brand-eyebrow">SOC OPENENV</p>
          <h1>Incident Response Console</h1>
        </div>

        <nav className="nav-links" aria-label="Main navigation">
          <NavLink to="/" className={({ isActive }) => (isActive ? "active" : "")}
          >
            Home
          </NavLink>
          <NavLink to="/about" className={({ isActive }) => (isActive ? "active" : "")}
          >
            About
          </NavLink>
        </nav>
      </header>

      <main>
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/about" element={<AboutPage />} />
        </Routes>
      </main>
    </div>
  );
}

export default App;
