import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { ArrowLeft, BookOpen, Download, Pencil, PlayCircle, Printer } from 'lucide-react';
import { PlaybookView } from '../components/playbook/PlaybookView';
import { StartInvestigationDialog } from '../components/StartInvestigationDialog';
import { Button, EmptyState, PageHeader, downloadFile } from '../components/ui';
import { useApp } from '../state/AppState';

export function PlaybookPage() {
  const { id = '' } = useParams();
  const { playbookById, notePlaybookOpened, settings, investigations } = useApp();
  const navigate = useNavigate();
  const pb = playbookById.get(id);
  const [startOpen, setStartOpen] = useState(false);

  useEffect(() => {
    if (pb) notePlaybookOpened(pb.id);
  }, [pb?.id]);

  if (!pb) {
    return (
      <EmptyState icon={<BookOpen className="h-8 w-8" aria-hidden />} title={`Playbook ${id} not found`} action={<Link to="/playbooks" className="text-accent hover:underline">Back to playbooks</Link>}>
        It may have been a local playbook that was deleted.
      </EmptyState>
    );
  }
  const open = investigations.filter((i) => i.playbookId === pb.id && i.status !== 'Resolved');

  return (
    <div>
      <Link to="/playbooks" className="no-print mb-2 inline-flex items-center gap-1 text-sm text-muted hover:text-fg">
        <ArrowLeft className="h-4 w-4" aria-hidden /> All playbooks
      </Link>
      <PageHeader
        title={pb.title}
        subtitle={<span className="font-mono">{pb.id}</span>}
        actions={
          <div className="no-print flex flex-wrap gap-2">
            <Button variant="primary" icon={<PlayCircle className="h-4 w-4" aria-hidden />} onClick={() => setStartOpen(true)}>
              Start Investigation
            </Button>
            {settings.role !== 'analyst' && (
              <Button icon={<Pencil className="h-4 w-4" aria-hidden />} onClick={() => navigate(`/playbooks/${pb.id}/edit`)}>
                Edit
              </Button>
            )}
            <Button icon={<Download className="h-4 w-4" aria-hidden />} onClick={() => downloadFile(`${pb.id}.json`, `${JSON.stringify(pb, null, 2)}\n`, 'application/json')}>
              Export JSON
            </Button>
            <Button icon={<Printer className="h-4 w-4" aria-hidden />} onClick={() => window.print()}>
              Print
            </Button>
          </div>
        }
      />
      {open.length > 0 && (
        <p className="no-print mb-3 text-sm text-muted">
          Open investigations using this playbook:{' '}
          {open.map((i, n) => (
            <span key={i.id}>
              {n > 0 && ', '}
              <Link to={`/investigations/${i.id}`} className="font-mono text-accent hover:underline">
                {i.id}
              </Link>
            </span>
          ))}
        </p>
      )}
      <PlaybookView pb={pb} />
      <StartInvestigationDialog open={startOpen} playbookId={pb.id} onClose={() => setStartOpen(false)} />
    </div>
  );
}
