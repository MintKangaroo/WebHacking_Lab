import { Card } from "../../components/ui/card";
import { Skeleton } from "../../components/ui/skeleton";

export function DashboardSkeleton() {
  return (
    <div className="space-y-6 p-4 sm:p-6 lg:p-8" aria-label="Loading dashboard">
      <div className="space-y-3">
        <Skeleton className="h-3 w-28" />
        <Skeleton className="h-8 w-72 max-w-full" />
        <Skeleton className="h-4 w-[460px] max-w-full" />
      </div>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        {Array.from({ length: 5 }, (_, index) => (
          <Card key={index} className="space-y-4 p-5">
            <Skeleton className="h-3 w-24" />
            <Skeleton className="h-8 w-16" />
          </Card>
        ))}
      </div>
      <div className="grid gap-4 xl:grid-cols-3">
        <Skeleton className="h-[330px] rounded-xl xl:col-span-2" />
        <Skeleton className="h-[330px] rounded-xl" />
      </div>
    </div>
  );
}
