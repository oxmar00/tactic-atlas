import { Link } from 'react-router';
import { Compass } from 'lucide-react';
import { EmptyState } from '../components/ui';

export function NotFoundPage() {
  return (
    <EmptyState icon={<Compass className="h-8 w-8" aria-hidden />} title="Page not found" action={<Link to="/" className="text-accent hover:underline">Back to the dashboard</Link>}>
      The address does not match any SOC Navigator view.
    </EmptyState>
  );
}
