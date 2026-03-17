import React from 'react';

export default function NavTabs({ pages, activePage, onPageChange }) {
  return (
    // Navigation Placeholder: Page Tabs
    <nav className="page-nav">
      {pages.map((page) => (
        <button
          key={page.id}
          type="button"
          className={`nav-btn ${activePage === page.id ? 'active' : ''}`}
          onClick={() => onPageChange(page.id)}
        >
          {page.label}
        </button>
      ))}
    </nav>
  );
}
