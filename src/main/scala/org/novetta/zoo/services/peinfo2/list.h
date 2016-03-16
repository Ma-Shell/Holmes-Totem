#pragma once
struct list_elem
{
	void* data;
	struct list_elem* next;
};

struct list
{
	struct list_elem* head;
	struct list_elem* tail;
};

void append(struct list* l, void* data)
{
	struct list_elem* elem = malloc(sizeof(struct list_elem));
	elem->next = NULL;
	elem->data = data;
	if(l->head == NULL)
	{
		l->head = elem;
		l->tail = elem;
	}
	else
	{
		l->tail->next = elem;
		l->tail = elem;
	}
}

void clear(struct list* l)
{
	struct list_elem* curr = l->head;
	struct list_elem* next = NULL;
	while(curr != NULL)
	{
		next = curr->next;
		free(curr);
		curr = next;
	}
	l->head = NULL;
	l->tail = NULL;
}