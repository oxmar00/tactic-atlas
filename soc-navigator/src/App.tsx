import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';
import { HashRouter, Route, Routes } from 'react-router';
import { Layout } from './components/Layout';
import { AppProvider } from './state/AppState';
import { DashboardPage } from './pages/DashboardPage';
import { InvestigationsPage } from './pages/InvestigationsPage';
import { MatrixPage } from './pages/MatrixPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { PlaybookEditorPage } from './pages/PlaybookEditorPage';
import { PlaybookPage } from './pages/PlaybookPage';
import { PlaybooksPage } from './pages/PlaybooksPage';
import { ReferencePage } from './pages/ReferencePage';
import { ReportPage } from './pages/ReportPage';
import { ReportsPage } from './pages/ReportsPage';
import { SettingsPage } from './pages/SettingsPage';
import { WorkspacePage } from './pages/WorkspacePage';

class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('SOC Navigator view error', error, info.componentStack);
  }
  render() {
    if (this.state.error) {
      return (
        <div role="alert" className="m-8 max-w-xl rounded-lg border border-bad/50 bg-bad/5 p-5">
          <p className="font-semibold text-fg-strong">This view failed to render.</p>
          <p className="mt-1 text-sm text-muted">{this.state.error.message}</p>
          <p className="mt-2 text-sm text-muted">Your saved investigations are not affected. Use the navigation to continue, or reload the page.</p>
          <button type="button" className="mt-3 rounded-md border border-line px-3 py-1.5 text-sm" onClick={() => this.setState({ error: null })}>
            Try again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

export function App() {
  return (
    <AppProvider>
      <HashRouter>
        <Layout>
          <ErrorBoundary>
            <Routes>
              <Route path="/" element={<DashboardPage />} />
              <Route path="/matrix" element={<MatrixPage />} />
              <Route path="/playbooks" element={<PlaybooksPage />} />
              <Route path="/playbooks/new" element={<PlaybookEditorPage />} />
              <Route path="/playbooks/:id" element={<PlaybookPage />} />
              <Route path="/playbooks/:id/edit" element={<PlaybookEditorPage />} />
              <Route path="/investigations" element={<InvestigationsPage />} />
              <Route path="/investigations/:id" element={<WorkspacePage />} />
              <Route path="/reference" element={<ReferencePage />} />
              <Route path="/reports" element={<ReportsPage />} />
              <Route path="/reports/:id" element={<ReportPage />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="*" element={<NotFoundPage />} />
            </Routes>
          </ErrorBoundary>
        </Layout>
      </HashRouter>
    </AppProvider>
  );
}
